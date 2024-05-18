package token

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleRefreshTokenGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.GrantSession,
	issues.OAuthError,
) {

	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	authenticatedClient, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err = validateRefreshTokenGrantRequest(req, authenticatedClient, grantSession); err != nil {
		return models.GrantSession{}, err
	}

	ctx.Logger.Debug("update the token session")
	updatedGrantSession, err := generateUpdatedGrantSession(ctx, grantSession)
	if err != nil {
		return models.GrantSession{}, err
	}

	return updatedGrantSession, nil
}

func getAuthenticatedClientAndGrantSession(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.Client,
	models.GrantSession,
	issues.OAuthError,
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
			Err:    issues.NewOAuthError(constants.InvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- utils.ResultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req models.TokenRequest,
) issues.OAuthError {
	if req.RefreshToken == "" || unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scope, req.CodeVerifier) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	req models.TokenRequest,
	client models.Client,
	grantSession models.GrantSession,
) issues.OAuthError {

	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scope, req.CodeVerifier) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	if !client.IsGrantTypeAllowed(constants.RefreshTokenGrant) {
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token is expired")
	}

	return nil
}

func generateUpdatedGrantSession(
	ctx utils.Context,
	grantSession models.GrantSession,
) (
	models.GrantSession,
	issues.OAuthError,
) {
	ctx.Logger.Debug("get the token model")
	grantModel, err := ctx.GrantModelManager.Get(grantSession.GrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	updatedGrantSession := grantModel.GenerateGrantSession(NewRefreshTokenGrantOptions(grantSession))
	updatedGrantSession.Id = grantSession.Id
	// Keep the same creation time to make sure the session will expire.
	updatedGrantSession.CreatedAtTimestamp = grantSession.CreatedAtTimestamp
	ctx.GrantSessionManager.CreateOrUpdate(updatedGrantSession)

	return updatedGrantSession, nil
}

func NewRefreshTokenGrantOptions(session models.GrantSession) models.GrantOptions {
	return models.GrantOptions{
		GrantType: constants.RefreshTokenGrant,
		Scopes:    session.Scopes,
		Subject:   session.Subject,
		ClientId:  session.ClientId,
		TokenOptions: models.TokenOptions{
			AdditionalTokenClaims: session.AdditionalTokenClaims,
		},
		IdTokenOptions: models.IdTokenOptions{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}
