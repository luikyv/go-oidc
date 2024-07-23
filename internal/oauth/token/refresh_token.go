package token

import (
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func handleRefreshTokenGrantTokenCreation(
	ctx *utils.Context,
	req utils.TokenRequest,
) (
	utils.TokenResponse,
	goidc.OAuthError,
) {
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return utils.TokenResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return utils.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantSession.GrantOptions)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, req, token); err != nil {
		return utils.TokenResponse{}, err
	}

	tokenResp := utils.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenLifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if utils.ScopesContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = utils.MakeIDToken(
			ctx,
			client,
			utils.NewIDTokenOptions(grantSession.GrantOptions),
		)
		if err != nil {
			return utils.TokenResponse{}, err
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx *utils.Context,
	grantSession *goidc.GrantSession,
	req utils.TokenRequest,
	token utils.Token,
) goidc.OAuthError {

	grantSession.LastTokenIssuedAtTimestamp = goidc.TimestampNow()
	grantSession.TokenID = token.ID

	if ctx.ShouldRotateRefreshTokens {
		token, err := utils.RefreshToken()
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
	ctx *utils.Context,
	req utils.TokenRequest,
) (
	*goidc.Client,
	*goidc.GrantSession,
	goidc.OAuthError,
) {

	grantSessionResultCh := make(chan utils.ResultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
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
	ctx *utils.Context,
	refreshToken string,
	ch chan<- utils.ResultChannel,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(refreshToken)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: nil,
			Err:    goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- utils.ResultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req utils.TokenRequest,
) goidc.OAuthError {
	if req.RefreshToken == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *utils.Context,
	req utils.TokenRequest,
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
	ctx *utils.Context,
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

	return utils.ValidateDPoPJWT(ctx, dpopJWT, utils.DPoPJWTValidationOptions{
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}
