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
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := authenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		return response{}, err
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return response{}, err
	}

	token, err := Make(ctx, client, NewGrantOptions(*grantSession))
	if err != nil {
		return response{}, err
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, req, token); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenOptions.LifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if strutil.ContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = MakeIDToken(
			ctx,
			client,
			newIDTokenOptions(NewGrantOptions(*grantSession)),
		)
		if err != nil {
			return response{}, err
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

	if ctx.RefreshToken.RotationIsEnabled {
		token, err := refreshToken()
		if err != nil {
			return oidcerr.New(oidcerr.CodeInternalError, err.Error())
		}
		grantSession.RefreshToken = token
	}

	if req.Scopes != "" {
		grantSession.ActiveScopes = req.Scopes
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return err
	}

	return nil
}

func authenticatedClientAndGrantSession(
	ctx *oidc.Context,
	req request,
) (
	*goidc.Client,
	*goidc.GrantSession,
	error,
) {

	grantSessionResultCh := make(chan resultChannel)
	go grantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return nil, nil, err
	}

	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.Result.(*goidc.GrantSession), grantSessionResult.Err
	if err != nil {
		return nil, nil, err
	}

	return c, grantSession, nil
}

func grantSessionByRefreshToken(
	ctx *oidc.Context,
	refreshToken string,
	ch chan<- resultChannel,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(refreshToken)
	if err != nil {
		ch <- resultChannel{
			Result: nil,
			Err:    oidcerr.New(oidcerr.CodeInvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- resultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req request,
) error {
	if req.RefreshToken == "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid refresh token")
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
		return oidcerr.New(oidcerr.CodeInvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return oidcerr.New(oidcerr.CodeInternalError, err.Error())
		}
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !containsAllScopes(grantSession.GrantedScopes, req.Scopes) {
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

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func refreshToken() (string, error) {
	return strutil.Random(RefreshTokenLength)
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
