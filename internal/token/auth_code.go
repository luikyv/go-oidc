package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthCodeToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	if req.code == "" {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("code is required"))
	}

	grant, err := ctx.GrantByAuthCode(req.code)
	if err != nil {
		if !errors.Is(err, goidc.ErrNotFound) {
			return response{}, fmt.Errorf("could not load the grant by auth code: %w", err)
		}
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", err)
	}

	if grant.RevokedAt != 0 {
		return response{}, goidc.WrapError(goidc.ErrorCodeExpiredToken, "invalid grant", errors.New("grant was revoked"))
	}

	resp, err := func() (response, error) {
		if grant.AuthCodeConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the authorization code has already been redeemed"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
			return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the authorization_code grant type"))
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the authorization code belongs to a different client"))
		}

		if timeutil.TimestampNow() >= grant.AuthCodeExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the authorization code has expired"))
		}

		if err := ValidateBinding(ctx, c, &bindindValidationOptions{
			tlsIsRequired:     grant.CertThumbprint != "",
			tlsCertThumbprint: grant.CertThumbprint,
			dpopIsRequired:    grant.JWKThumbprint != "",
			dpopJWKThumbprint: grant.JWKThumbprint,
		}); err != nil {
			return response{}, err
		}

		if req.redirectURI != grant.AuthParams.RedirectURI {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the redirect_uri does not match the authorization code"))
		}

		if err := validatePKCE(ctx, req, grant); err != nil {
			return response{}, err
		}

		if err := validateResources(ctx, req, grant.Resources); err != nil {
			return response{}, err
		}

		if err := validateAuthDetails(ctx, req, c, grant.AuthDetails); err != nil {
			return response{}, err
		}

		if err := validateVerifiableCredentials(ctx, grant); err != nil {
			return response{}, err
		}

		if err := validateScopes(ctx, req, c, grant.Scopes); err != nil {
			return response{}, err
		}

		grant.JWKThumbprint = dpopThumbprint(ctx)
		grant.CertThumbprint = tlsThumbprint(ctx)
		grant.AuthCodeConsumedAt = timeutil.TimestampNow()
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

		resp := response{
			AccessToken:          tokenValue,
			ExpiresIn:            tkn.LifetimeSecs(),
			TokenType:            tkn.Type,
			RefreshToken:         grant.RefreshToken,
			Scopes:               tkn.Scopes,
			AuthorizationDetails: tkn.AuthDetails,
			Resources:            tkn.Resources,
		}
		if strutil.ContainsOpenID(tkn.Scopes) {
			resp.IDToken, err = MakeIDToken(ctx, c, IDTokenOptions{
				Subject: grant.Subject,
				Nonce:   grant.AuthParams.Nonce,
				Claims:  ctx.IDTokenClaims(grant),
			})
			if err != nil {
				return response{}, fmt.Errorf("could not generate id token for the authorization code grant: %w", err)
			}
		}
		return resp, nil
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

func validateVerifiableCredentials(ctx oidc.Context, grant *goidc.Grant) error {
	if !ctx.VCIsEnabled {
		return nil
	}

	if _, _, err := vc.Resolve(ctx, vc.Request{
		Scopes:    grant.Scopes,
		Details:   grant.AuthDetails,
		Resources: grant.Resources,
	}); err != nil {
		return err
	}

	return nil
}
