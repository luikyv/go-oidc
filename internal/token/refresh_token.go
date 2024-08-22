package token

import (
	"slices"
	"time"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(
	ctx *oidc.Context,
	req request,
) (
	response,
	oidc.Error,
) {
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return response{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid parameter for refresh token grant")
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
) oidc.Error {

	grantSession.LastTokenIssuedAtTimestamp = time.Now().Unix()
	grantSession.TokenID = token.ID

	if ctx.RefreshToken.RotationIsEnabled {
		token, err := refreshToken()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
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
	oidc.Error,
) {

	grantSessionResultCh := make(chan resultChannel)
	go grantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	c, err := client.Authenticated(ctx, req.AuthnRequest)
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
			Err:    oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- resultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req request,
) oidc.Error {
	if req.RefreshToken == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *oidc.Context,
	req request,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) oidc.Error {

	if !client.IsGrantTypeAllowed(goidc.GrantRefreshToken) {
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if client.ID != grantSession.ClientID {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !containsAllScopes(grantSession.GrantedScopes, req.Scopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidScope, "invalid scope")
	}

	return validateRefreshTokenPoPForPublicClients(ctx, client, grantSession)
}

func validateRefreshTokenPoPForPublicClients(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) oidc.Error {

	// TODO: Validate the certificate?

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.ClientAuthnNone || grantSession.JWKThumbprint == "" {
		return nil
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
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
