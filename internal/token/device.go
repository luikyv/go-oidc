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
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("device_code is required"))
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	grant, err := ctx.GrantByDeviceCode(req.deviceCode)
	if err != nil {
		if !errors.Is(err, goidc.ErrNotFound) {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", fmt.Errorf("could not load the grant by device code: %w", err))
		}

		as, sessionErr := ctx.DeviceSessionByDeviceCode(req.deviceCode)
		if sessionErr != nil {
			if !errors.Is(sessionErr, goidc.ErrNotFound) {
				return response{}, fmt.Errorf("could not load authn session: %w", sessionErr)
			}
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("no grant or pending device session was found for the device code"))
		}

		if as.ClientID != c.ID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("authn session was not issued for this client"))
		}

		if timeutil.TimestampNow() >= as.ExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "device code expired", errors.New("grant was not found and the pending device session has expired"))
		}

		if as.Status == goidc.StatusFailure {
			return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the authentication session was denied"))
		}

		return response{}, goidc.WrapError(goidc.ErrorCodeAuthPending, "authentication pending", errors.New("grant was not found and the pending device session is still awaiting approval"))
	}

	if grant.RevokedAt != 0 {
		return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "invalid grant", errors.New("grant was revoked"))
	}

	resp, err := func() (response, error) {
		if timeutil.TimestampNow() >= grant.DeviceCodeExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "device code expired", errors.New("the device code lifetime has elapsed"))
		}

		if grant.DeviceCodeConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the device code has already been redeemed"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantDeviceCode) {
			return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the device_code grant type"))
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the device code belongs to a different client"))
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
		grant.RevokedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return response{}, fmt.Errorf("could not revoke grant: %w", err)
		}
		return response{}, err
	}
	return resp, nil
}
