package token

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleRefreshTokenGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.TokenResponse,
	models.OAuthError,
) {

	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return models.TokenResponse{}, models.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.TokenResponse{}, err
	}

	if err = validateRefreshTokenGrantRequest(req, client, grantSession); err != nil {
		return models.TokenResponse{}, err
	}

	token := utils.MakeToken(ctx, client, grantSession.GrantOptions)
	tokenResp := models.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantSession.ExpiresInSecs,
		TokenType:   token.Type,
	}

	if unit.ScopesContainsOpenId(grantSession.Scopes) {
		tokenResp.IdToken = utils.MakeIdToken(ctx, client, grantSession.GrantOptions)
	}

	updateRefreshTokenGrantSession(ctx, grantSession)
	tokenResp.RefreshToken = grantSession.RefreshToken
	return tokenResp, nil
}

func updateRefreshTokenGrantSession(ctx utils.Context, grantSession models.GrantSession) models.OAuthError {
	grantSession.RenewedAtTimestamp = unit.GetTimestampNow()
	if ctx.ShouldRotateRefreshToken {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
	}

	err := ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	if err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func getAuthenticatedClientAndGrantSession(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.Client,
	models.GrantSession,
	models.OAuthError,
) {

	ctx.Logger.Debug("get the token session using the refresh token.")
	grantSessionResultCh := make(chan utils.ResultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	ctx.Logger.Debug("get the client while the token is being loaded.")
	authenticatedClient, err := GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.Result.(models.GrantSession), grantSessionResult.Err
	if err != nil {
		ctx.Logger.Debug("error while loading the token.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(
	ctx utils.Context,
	refreshToken string,
	ch chan<- utils.ResultChannel,
) {
	grantSession, err := ctx.GrantSessionManager.GetByRefreshToken(refreshToken)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.GrantSession{},
			Err:    models.NewOAuthError(constants.InvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- utils.ResultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req models.TokenRequest,
) models.OAuthError {
	if req.RefreshToken == "" || unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scopes, req.CodeVerifier) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	req models.TokenRequest,
	client models.Client,
	grantSession models.GrantSession,
) models.OAuthError {

	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scopes, req.CodeVerifier) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	if !client.IsGrantTypeAllowed(constants.RefreshTokenGrant) {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return models.NewOAuthError(constants.UnauthorizedClient, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return models.NewOAuthError(constants.UnauthorizedClient, "the refresh token is expired")
	}

	return nil
}
