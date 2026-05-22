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

func generateRefreshToken(ctx oidc.Context, req request) (response, error) {
	if req.refreshToken == "" {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			fmt.Errorf("refresh_token is required"))
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	grant, err := ctx.RefreshGrantByRefreshToken(req.refreshToken)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", fmt.Errorf("could not load the grant by refresh token: %w", err))
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) {
		return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", fmt.Errorf("the client is not allowed to use the %s grant type", goidc.GrantRefreshToken))
	}

	if c.ID != grant.ClientID {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", fmt.Errorf("the refresh token belongs to client %q, not %q", grant.ClientID, c.ID))
	}

	if grant.RevokedAt != 0 {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("the grant associated to the refresh token was revoked"))
	}

	if grant.RefreshTokenExpiresAt != 0 && timeutil.TimestampNow() >= grant.RefreshTokenExpiresAt {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", fmt.Errorf("the refresh token expired at %d", grant.RefreshTokenExpiresAt))
	}

	cnf := goidc.TokenConfirmation{
		JWKThumbprint:  grant.JWKThumbprint,
		CertThumbprint: grant.CertThumbprint,
	}
	if err := validateRefreshTokenBinding(ctx, c, cnf); err != nil {
		return response{}, err
	}

	if err := validateRefreshTokenPoP(ctx, c, cnf); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, grant.Scopes); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, grant.Resources); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, grant.AuthDetails); err != nil {
		return response{}, err
	}

	var refreshToken string
	if ctx.RefreshTokenRotationIsEnabled {
		refreshToken = ctx.RefreshToken()
		grant.RefreshToken = refreshToken
		if ctx.RefreshTokenLifetimeSecs != 0 {
			grant.RefreshTokenExpiresAt = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
		} else {
			grant.RefreshTokenExpiresAt = 0
		}
	}
	// Re-derive the token binding thumbprints from the current request.
	// Only grants already bound to DPoP or TLS are updated; unbound grants stay unbound.
	// The new values will match the originals during proof of possession (validation
	// ensures this), but the explicit assignment keeps the intent clear.
	if grant.JWKThumbprint != "" {
		grant.JWKThumbprint = dpopThumbprint(ctx)
	}
	if grant.CertThumbprint != "" {
		grant.CertThumbprint = tlsThumbprint(ctx)
	}
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
		Scopes:               tkn.Scopes,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
		RefreshToken:         refreshToken,
	}

	if strutil.ContainsOpenID(tkn.Scopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, c, IDTokenOptions{
			Subject: grant.Subject,
			Nonce:   grant.AuthParams.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token during refresh token grant: %w", err)
		}
	}

	return tokenResp, nil
}

func validateRefreshTokenBinding(ctx oidc.Context, c *goidc.Client, cnf goidc.TokenConfirmation) error {
	// For public clients, tokens are bound to the mechanism specified when
	// issuing the first token.
	// In that case proof of possession is verified instead of token binding.
	if c.IsPublic() {
		return nil
	}

	// If the refresh token was issued with DPoP, make sure the following token is bound with DPoP as well.
	if cnf.JWKThumbprint != "" {
		// Note that a DPoP JWT for a different key can be used to bind the token.
		opts := bindindValidationOptions{}
		opts.dpopIsRequired = true
		if err := validateBindingDPoP(ctx, c, opts); err != nil {
			return err
		}
	}

	// If the refresh token was issued with TLS binding, make sure the following
	// token is bound to the same tls certificate.
	if cnf.CertThumbprint != "" {
		opts := bindindValidationOptions{
			tlsIsRequired:     true,
			tlsCertThumbprint: cnf.CertThumbprint,
		}
		if err := validateBindingTLS(ctx, c, opts); err != nil {
			return err
		}
	}

	return nil
}

func validateRefreshTokenPoP(ctx oidc.Context, c *goidc.Client, cnf goidc.TokenConfirmation) error {
	// Proof of possession validation is not needed during the refresh token
	// for confidential clients, as they are already authenticated.
	if !c.IsPublic() {
		return nil
	}

	return ValidatePoP(ctx, "", cnf)
}
