package token

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleClientCredentialsGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.TokenResponse,
	models.OAuthError,
) {
	client, oauthErr := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	grantOptions, err := newClientCredentialsGrantOptions(ctx, client, req)
	if err != nil {
		return models.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantOptions)
	if err != nil {
		return models.TokenResponse{}, err
	}

	_, oauthErr = generateClientCredentialsGrantSession(ctx, client, token, grantOptions)
	if oauthErr != nil {
		return models.TokenResponse{}, nil
	}

	tokenResp := models.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenExpiresInSecs,
		TokenType:   token.Type,
	}

	if req.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	return tokenResp, nil
}

func generateClientCredentialsGrantSession(
	ctx utils.Context,
	_ models.Client,
	token models.Token,
	grantOptions models.GrantOptions,
) (models.GrantSession, models.OAuthError) {

	grantSession := models.NewGrantSession(grantOptions, token)
	// WARNING: This will cause problems if something goes wrong.
	go func() {
		ctx.Logger.Debug("creating grant session for client_credentials grant")
		if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
			ctx.Logger.Error("error creating a grant session during client_credentials grant",
				slog.String("error", err.Error()))
		}
	}()

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

	if unit.ScopesContainsOpenId(req.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "cannot request openid scope for client credentials grant")
	}

	if !client.AreScopesAllowed(req.Scopes) {
		ctx.Logger.Info("scope not allowed")
		return models.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if err := validateTokenBindingRequestWithDpop(ctx, req, client); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	return nil
}

func newClientCredentialsGrantOptions(
	ctx utils.Context,
	client models.Client,
	req models.TokenRequest,
) (
	models.GrantOptions,
	models.OAuthError,
) {
	tokenOptions, err := ctx.GetTokenOptions(client, req.Scopes)
	if err != nil {
		return models.GrantOptions{}, models.NewOAuthError(constants.AccessDenied, err.Error())
	}

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
	}, nil
}
