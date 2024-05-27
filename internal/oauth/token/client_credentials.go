package token

import (
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
	models.OAuthError,
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

	grantSession := utils.GenerateGrantSession(ctx, client, newClientCredentialsGrantOptions(ctx, client, req))
	return grantSession, nil
}

func preValidateClientCredentialsGrantRequest(req models.TokenRequest) models.OAuthError {
	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.RefreshToken, req.CodeVerifier) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid parameter for client credentials grant")
	}

	if unit.ScopesContainsOpenId(req.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "cannot request openid scope for client credentials grant")
	}

	return nil
}

func validateClientCredentialsGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
) models.OAuthError {

	if !client.IsGrantTypeAllowed(constants.ClientCredentialsGrant) {
		ctx.Logger.Info("grant type not allowed")
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if !client.AreScopesAllowed(req.Scopes) {
		ctx.Logger.Info("scope not allowed")
		return models.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func newClientCredentialsGrantOptions(ctx utils.Context, client models.Client, req models.TokenRequest) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(client.Attributes, req.Scopes)
	return models.GrantOptions{
		GrantType:    constants.ClientCredentialsGrant,
		Scopes:       req.Scopes,
		Subject:      client.Id,
		ClientId:     client.Id,
		DpopJwt:      req.DpopJwt,
		TokenOptions: tokenOptions,
		IdTokenOptions: models.IdTokenOptions{
			AdditionalIdTokenClaims: make(map[string]string),
		},
	}
}
