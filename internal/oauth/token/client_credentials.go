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
	models.TokenResponse,
	models.OAuthError,
) {
	if oauthErr := preValidateClientCredentialsGrantRequest(req); oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	client, oauthErr := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	grantOptions := newClientCredentialsGrantOptions(ctx, client, req)
	token := utils.MakeToken(ctx, client, grantOptions)
	tokenResp := models.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenExpiresInSecs,
		TokenType:   token.Type,
	}

	if req.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	if !shouldGenerateClientCredentialsGrantSession(ctx, grantOptions) {
		return tokenResp, nil
	}

	_, err := generateClientCredentialsGrantSession(ctx, client, token, grantOptions)
	if err != nil {
		return models.TokenResponse{}, nil
	}
	return tokenResp, nil
}

func preValidateClientCredentialsGrantRequest(req models.TokenRequest) models.OAuthError {
	if unit.ScopesContainsOpenId(req.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "cannot request openid scope for client credentials grant")
	}

	return nil
}

func shouldGenerateClientCredentialsGrantSession(_ utils.Context, grantOptions models.GrantOptions) bool {
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat
}

func generateClientCredentialsGrantSession(
	ctx utils.Context,
	_ models.Client,
	token models.Token,
	grantOptions models.GrantOptions,
) (models.GrantSession, models.OAuthError) {
	grantSession := models.NewGrantSession(grantOptions, token)
	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.GrantSession{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return grantSession, nil
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

	return utils.ValidateTokenBindingRequestWithDpop(ctx, req, client)
}

func newClientCredentialsGrantOptions(ctx utils.Context, client models.Client, req models.TokenRequest) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(client, req.Scopes)
	scopes := req.Scopes
	if scopes == "" {
		scopes = client.Scopes
	}
	return models.GrantOptions{
		GrantType:     constants.ClientCredentialsGrant,
		GrantedScopes: scopes,
		Subject:       client.Id,
		ClientId:      client.Id,
		TokenOptions:  tokenOptions,
	}
}
