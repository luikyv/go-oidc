package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(
	ctx *oidc.Context,
	req request,
) (
	response,
	error,
) {
	if req.refreshToken == "" {
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest,
			"invalid refresh token")
	}

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return response{}, err
	}

	grantSession, err := ctx.GrantSessionByRefreshToken(req.refreshToken)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"invalid refresh_token", err)
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, c, grantSession); err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, NewGrantOptions(*grantSession))
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate token during refresh token grant", err)
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, req, token); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken: token.Value,
		ExpiresIn:   grantSession.TokenOptions.LifetimeSecs,
		TokenType:   token.Type,
	}

	if ctx.RefreshTokenRotationIsEnabled {
		tokenResp.RefreshToken = grantSession.RefreshToken
	}

	if strutil.ContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = MakeIDToken(
			ctx,
			c,
			newIDTokenOptions(NewGrantOptions(*grantSession)),
		)
		if err != nil {
			return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
				"could not generate id token during refresh token grant", err)
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx *oidc.Context,
	grantSession *goidc.GrantSession,
	req request,
	token Token,
) error {

	grantSession.LastTokenIssuedAtTimestamp = timeutil.TimestampNow()
	grantSession.TokenID = token.ID

	if ctx.RefreshTokenRotationIsEnabled {
		token, err := refreshToken()
		if err != nil {
			return err
		}
		grantSession.RefreshToken = token
	}

	if req.scopes != "" {
		grantSession.ActiveScopes = req.scopes
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not store the grant session", err)
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *oidc.Context,
	req request,
	c *goidc.Client,
	grantSession *goidc.GrantSession,
) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) {
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != grantSession.ClientID {
		return oidcerr.New(oidcerr.CodeInvalidGrant,
			"the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return oidcerr.Errorf(oidcerr.CodeInternalError,
				"internal error", err)
		}
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "the refresh token is expired")
	}

	if req.scopes != "" && !containsAllScopes(grantSession.GrantedScopes, req.scopes) {
		return oidcerr.New(oidcerr.CodeInvalidScope, "invalid scope")
	}

	return validateRefreshTokenPoPForPublicClients(ctx, c, grantSession)
}

func validateRefreshTokenPoPForPublicClients(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) error {

	// TODO: Validate the certificate?

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.ClientAuthnNone || grantSession.JWKThumbprint == "" {
		return nil
	}

	dpopJWT, ok := dpopJWT(ctx)
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{
		jwkThumbprint: grantSession.JWKThumbprint,
	})
}

func refreshToken() (string, error) {
	token, err := strutil.Random(goidc.RefreshTokenLength)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate the refresh token", err)
	}
	return token, nil
}

func containsAllScopes(availableScopes string, requestedScopes string) bool {
	scopeSlice := strutil.SplitWithSpaces(availableScopes)
	for _, e := range strutil.SplitWithSpaces(requestedScopes) {
		if !slices.Contains(scopeSlice, e) {
			return false
		}
	}

	return true
}
