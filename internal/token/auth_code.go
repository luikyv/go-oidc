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

func generateAuthCodeGrantToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	if req.code == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "missing auth code")
	}

	grant, err := ctx.GrantByAuthCode(req.code)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", err)
	}

	resp, err := func() (response, error) {
		if grant.AuthCodeConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", errors.New("auth code already used"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
			return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "invalid grant", errors.New("client is not allowed to use auth code grant"))
		}

		if c.ID != grant.ClientID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the authorization code was not issued to the client"))
		}

		if timeutil.TimestampNow() > grant.CreatedAt+ctx.AuthCodeLifetimeSecs {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the auth code is expired"))
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
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
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
		_ = ctx.DeleteGrant(grant.ID)
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
