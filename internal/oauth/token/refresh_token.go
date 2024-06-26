package token

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func handleRefreshTokenGrantTokenCreation(
	ctx utils.Context,
	req utils.TokenRequest,
) (
	utils.TokenResponse,
	goidc.OAuthError,
) {
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return utils.TokenResponse{}, goidc.NewOAuthError(goidc.InvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return utils.TokenResponse{}, err
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return utils.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantSession.GrantOptions)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	updateRefreshTokenGrantSession(ctx, &grantSession, req, token)

	tokenResp := utils.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenExpiresInSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if utils.ScopesContainsOpenId(grantSession.ActiveScopes) {
		tokenResp.IdToken, err = utils.MakeIdToken(
			ctx,
			client,
			utils.NewIdTokenOptions(grantSession.GrantOptions),
		)
		if err != nil {
			ctx.Logger.Error("could not generate an ID token", slog.String("error", err.Error()))
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx utils.Context,
	grantSession *goidc.GrantSession,
	req utils.TokenRequest,
	token utils.Token,
) goidc.OAuthError {

	grantSession.LastTokenIssuedAtTimestamp = goidc.GetTimestampNow()
	grantSession.TokenId = token.Id

	if ctx.ShouldRotateRefreshTokens {
		grantSession.RefreshToken = utils.GenerateRefreshToken()
	}

	if req.Scopes != "" {
		grantSession.ActiveScopes = req.Scopes
	}

	ctx.Logger.Debug("updating grant session for refresh_token grant")
	if err := ctx.CreateOrUpdateGrantSession(*grantSession); err != nil {
		ctx.Logger.Error("error updating grant session during refresh_token grant",
			slog.String("error", err.Error()), slog.String("session_id", grantSession.Id))
		return goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func getAuthenticatedClientAndGrantSession(
	ctx utils.Context,
	req utils.TokenRequest,
) (
	goidc.Client,
	goidc.GrantSession,
	goidc.OAuthError,
) {

	ctx.Logger.Debug("get the token session using the refresh token.")
	grantSessionResultCh := make(chan utils.ResultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	ctx.Logger.Debug("get the client while the token is being loaded.")
	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return goidc.Client{}, goidc.GrantSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.Result.(goidc.GrantSession), grantSessionResult.Err
	if err != nil {
		ctx.Logger.Debug("error while loading the token.", slog.String("error", err.Error()))
		return goidc.Client{}, goidc.GrantSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(
	ctx utils.Context,
	refreshToken string,
	ch chan<- utils.ResultChannel,
) {
	grantSession, err := ctx.GetGrantSessionByRefreshToken(refreshToken)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: goidc.GrantSession{},
			Err:    goidc.NewOAuthError(goidc.InvalidRequest, "invalid refresh_token"),
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
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx utils.Context,
	req utils.TokenRequest,
	client goidc.Client,
	grantSession goidc.GrantSession,
) goidc.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.RefreshTokenGrant) {
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return goidc.NewOAuthError(goidc.InvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		if err := ctx.DeleteGrantSession(grantSession.Id); err != nil {
			return goidc.NewOAuthError(goidc.InternalError, err.Error())
		}
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !goidc.ContainsAllScopes(grantSession.GrantedScopes, req.Scopes) {
		return goidc.NewOAuthError(goidc.InvalidScope, "invalid scope")
	}

	return validateRefreshTokenProofOfPossesionForPublicClients(ctx, client, grantSession)
}

func validateRefreshTokenProofOfPossesionForPublicClients(
	ctx utils.Context,
	client goidc.Client,
	grantSession goidc.GrantSession,
) goidc.OAuthError {

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.NoneAuthn || grantSession.JwkThumbprint == "" {
		return nil
	}

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "invalid DPoP header")
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, utils.DpopJwtValidationOptions{
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}
