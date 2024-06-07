package token

import (
	"log/slog"
	"net/http"

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

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return models.TokenResponse{}, err
	}

	token := utils.MakeToken(ctx, client, grantSession.GrantOptions)
	updateRefreshTokenGrantSession(ctx, &grantSession, req, token)

	tokenResp := models.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenExpiresInSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if unit.ScopesContainsOpenId(grantSession.ActiveScopes) {
		tokenResp.IdToken = utils.MakeIdToken(ctx, client, grantSession.GrantOptions)
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx utils.Context,
	grantSession *models.GrantSession,
	req models.TokenRequest,
	token models.Token,
) models.OAuthError {
	grantSession.LastTokenIssuedAtTimestamp = unit.GetTimestampNow()
	grantSession.TokenId = token.Id

	if ctx.ShouldRotateRefreshTokens {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
	}

	if req.Scopes != "" {
		grantSession.ActiveScopes = req.Scopes
	}

	if err := ctx.GrantSessionManager.CreateOrUpdate(*grantSession); err != nil {
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
	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
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
	if req.RefreshToken == "" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
	grantSession models.GrantSession,
) models.OAuthError {

	if !client.IsGrantTypeAllowed(constants.RefreshTokenGrant) {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return models.NewOAuthError(constants.InvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return models.NewOAuthError(constants.UnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !unit.ContainsAllScopes(grantSession.GrantedScopes, req.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateRefreshTokenProofOfPossesionForPublicClients(ctx, client, grantSession)
}

func validateRefreshTokenProofOfPossesionForPublicClients(
	ctx utils.Context,
	client models.Client,
	grantSession models.GrantSession,
) models.OAuthError {

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != constants.NoneAuthn || grantSession.JwkThumbprint == "" {
		return nil
	}

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return models.NewOAuthError(constants.AccessDenied, "missing DPoP header")
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, models.DpopValidationOptions{
		HttpMethod:    http.MethodPost,
		HttpUri:       ctx.Host + string(constants.TokenEndpoint),
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}
