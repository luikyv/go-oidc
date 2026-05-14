package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateDeviceCodeToken(ctx oidc.Context, req request) (response, error) {
	if req.deviceCode == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "device_code is required")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	grant, err := ctx.GrantByDeviceCode(req.deviceCode)
	if err != nil {
		if !errors.Is(err, goidc.ErrNotFound) {
			return response{}, err
		}

		as, sessionErr := ctx.DeviceSessionByDeviceCode(req.deviceCode)
		if sessionErr != nil {
			if errors.Is(sessionErr, goidc.ErrNotFound) {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid device code")
			}
			return response{}, sessionErr
		}
		if as.IsExpired() {
			_ = ctx.DeviceDeleteSession(as.ID)
			return response{}, goidc.NewError(goidc.ErrorCodeExpiredToken, "device code expired")
		}
		// The session exists so it's still in progress.
		return response{}, goidc.NewError(goidc.ErrorCodeAuthPending, "authentication pending")
	}

	resp, err := func() (response, error) {
		if timeutil.TimestampNow() >= grant.DeviceCodeExpiresAt {
			return response{}, goidc.NewError(goidc.ErrorCodeExpiredToken, "device code expired")
		}

		if grant.DeviceCodeConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid device code", errors.New("device code already used"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantDeviceCode) {
			return response{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidGrant, "the device code was not issued to the client")
		}

		if err := validateResources(ctx, req, grant.Resources); err != nil {
			return response{}, err
		}

		if err := validateAuthDetails(ctx, req, c, grant.AuthDetails); err != nil {
			return response{}, err
		}

		if err := validateScopes(ctx, req, c, grant.Scopes); err != nil {
			return response{}, err
		}

		grant.JWKThumbprint = dpopThumbprint(ctx)
		grant.CertThumbprint = tlsThumbprint(ctx)
		grant.DeviceCodeConsumedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return response{}, err
		}

		tkn, tokenValue, err := Issue(ctx, grant, c, &IssuanceOptions{
			Scopes:      req.scopes,
			AuthDetails: req.authDetails,
			Resources:   req.resources,
		})
		if err != nil {
			return response{}, err
		}

		tokenResp := response{
			AccessToken:          tokenValue,
			ExpiresIn:            tkn.LifetimeSecs(),
			TokenType:            tkn.Type,
			RefreshToken:         grant.RefreshToken,
			Scopes:               tkn.Scopes,
			AuthorizationDetails: tkn.AuthDetails,
			Resources:            tkn.Resources,
		}
		if strutil.ContainsOpenID(tkn.Scopes) {
			tokenResp.IDToken, err = MakeIDToken(ctx, c, IDTokenOptions{
				Subject: grant.Subject,
				Nonce:   grant.AuthParams.Nonce,
				Claims:  ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return response{}, fmt.Errorf("could not generate id token for the device code grant: %w", err)
			}
		}

		return tokenResp, nil
	}()
	if err != nil {
		_ = ctx.DeleteGrant(grant.ID)
		_ = ctx.DeleteTokenByGrantID(grant.ID)
		return response{}, err
	}
	return resp, nil
}
