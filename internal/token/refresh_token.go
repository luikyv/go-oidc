package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(ctx oidc.Context, req request) (response, error) {
	if req.refreshToken == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	grant, err := ctx.GrantByRefreshToken(req.refreshToken)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid refresh_token", err)
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, c, grant); err != nil {
		return response{}, err
	}

	var refreshToken string
	if ctx.RefreshTokenRotationIsEnabled {
		refreshToken = ctx.RefreshToken()
		grant.RefreshToken = refreshToken
		grant.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
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

	if err := ctx.HandleGrant(grant); err != nil {
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
			Nonce:   grant.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token during refresh token grant: %w", err)
		}
	}

	return tokenResp, nil
}

func validateRefreshTokenGrantRequest(ctx oidc.Context, req request, c *goidc.Client, grant *goidc.Grant) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != grant.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the refresh token was not issued to the client")
	}

	if grant.IsExpired() {
		_ = ctx.DeleteGrant(grant.ID)
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	cnf := goidc.TokenConfirmation{
		JWKThumbprint:  grant.JWKThumbprint,
		CertThumbprint: grant.CertThumbprint,
	}
	if err := validateRefreshTokenBinding(ctx, c, cnf); err != nil {
		return err
	}

	if err := validateRefreshTokenPoP(ctx, c, cnf); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, c, grant.Scopes); err != nil {
		return err
	}

	if err := validateResources(ctx, req, grant.Resources); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, req, c, grant.AuthDetails); err != nil {
		return err
	}

	return nil
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
