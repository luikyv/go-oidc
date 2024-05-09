package token

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleClientCredentialsGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.GrantSession,
	issues.OAuthError,
) {
	if oauthErr := preValidateClientCredentialsGrantRequest(req); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	client, oauthErr := GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	grantModel, err := ctx.GrantModelManager.Get(client.DefaultGrantModelId)
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "grant model not found")
	}

	grantSession := grantModel.GenerateGrantSession(models.NewClientCredentialsGrantOptions(client, req))

	if shouldCreateGrantSessionForClientCredentialsGrant(grantSession) {
		// We only need to create a token session for client credentials when the token is not self-contained,
		// i.e. it is a refecence token.
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "grant session not created")
	}

	return grantSession, nil
}

func preValidateClientCredentialsGrantRequest(req models.TokenRequest) issues.OAuthError {
	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.RefreshToken, req.CodeVerifier) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for client credentials grant")
	}

	return nil
}

func validateClientCredentialsGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
) issues.OAuthError {

	if !client.IsGrantTypeAllowed(constants.ClientCredentialsGrant) {
		ctx.Logger.Info("grant type not allowed")
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		ctx.Logger.Info("scope not allowed")
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func shouldCreateGrantSessionForClientCredentialsGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained.
	return grantSession.TokenFormat == constants.Opaque
}
