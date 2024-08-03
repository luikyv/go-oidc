package token

import (
	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleRefreshTokenGrantTokenCreation(
	ctx *oidc.Context,
	req tokenRequest,
) (
	tokenResponse,
	goidc.OAuthError,
) {
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return tokenResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		return tokenResponse{}, err
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return tokenResponse{}, err
	}

	token, err := Make(ctx, client, grantSession.GrantOptions)
	if err != nil {
		return tokenResponse{}, err
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, req, token); err != nil {
		return tokenResponse{}, err
	}

	tokenResp := tokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenLifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if goidc.ScopesContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = MakeIDToken(
			ctx,
			client,
			newIDTokenOptions(grantSession.GrantOptions),
		)
		if err != nil {
			return tokenResponse{}, err
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx *oidc.Context,
	grantSession *goidc.GrantSession,
	req tokenRequest,
	token Token,
) goidc.OAuthError {

	grantSession.LastTokenIssuedAtTimestamp = goidc.TimestampNow()
	grantSession.TokenID = token.ID

	if ctx.ShouldRotateRefreshTokens {
		token, err := refreshToken()
		if err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		grantSession.RefreshToken = token
	}

	if req.Scopes != "" {
		grantSession.ActiveScopes = req.Scopes
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func getAuthenticatedClientAndGrantSession(
	ctx *oidc.Context,
	req tokenRequest,
) (
	*goidc.Client,
	*goidc.GrantSession,
	goidc.OAuthError,
) {

	grantSessionResultCh := make(chan resultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	authenticatedClient, err := authn.Client(ctx, req.ClientAuthnRequest)
	if err != nil {
		return nil, nil, err
	}

	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.Result.(*goidc.GrantSession), grantSessionResult.Err
	if err != nil {
		return nil, nil, err
	}

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(
	ctx *oidc.Context,
	refreshToken string,
	ch chan<- resultChannel,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(refreshToken)
	if err != nil {
		ch <- resultChannel{
			Result: nil,
			Err:    goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- resultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req tokenRequest,
) goidc.OAuthError {
	if req.RefreshToken == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *oidc.Context,
	req tokenRequest,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) goidc.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.GrantRefreshToken) {
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if client.ID != grantSession.ClientID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !goidc.ContainsAllScopes(grantSession.GrantedScopes, req.Scopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	return validateRefreshTokenProofOfPossesionForPublicClients(ctx, client, grantSession)
}

func validateRefreshTokenProofOfPossesionForPublicClients(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) goidc.OAuthError {

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.ClientAuthnNone || grantSession.JWKThumbprint == "" {
		return nil
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, DPoPJWTValidationOptions{
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func refreshToken() (string, error) {
	return goidc.RandomString(goidc.RefreshTokenLength)
}
