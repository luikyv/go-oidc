package token

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func handleClientCredentialsGrantTokenCreation(
	ctx utils.OAuthContext,
	req utils.TokenRequest,
) (
	utils.TokenResponse,
	goidc.OAuthError,
) {
	client, oauthErr := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return utils.TokenResponse{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return utils.TokenResponse{}, oauthErr
	}

	grantOptions, err := newClientCredentialsGrantOptions(ctx, client, req)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantOptions)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	_, oauthErr = generateClientCredentialsGrantSession(ctx, client, token, grantOptions)
	if oauthErr != nil {
		return utils.TokenResponse{}, nil
	}

	tokenResp := utils.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenLifetimeSecs,
		TokenType:   token.Type,
	}

	if req.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	return tokenResp, nil
}

func generateClientCredentialsGrantSession(
	ctx utils.OAuthContext,
	_ goidc.Client,
	token utils.Token,
	grantOptions goidc.GrantOptions,
) (goidc.GrantSession, goidc.OAuthError) {

	grantSession := utils.NewGrantSession(grantOptions, token)
	ctx.Logger().Debug("creating grant session for client_credentials grant")
	if err := ctx.CreateOrUpdateGrantSession(grantSession); err != nil {
		ctx.Logger().Error("error creating a grant session during client_credentials grant",
			slog.String("error", err.Error()))
		return goidc.GrantSession{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return grantSession, nil
}

func validateClientCredentialsGrantRequest(
	ctx utils.OAuthContext,
	req utils.TokenRequest,
	client goidc.Client,
) goidc.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.GrantClientCredentials) {
		ctx.Logger().Info("grant type not allowed")
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if utils.ScopesContainsOpenID(req.Scopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidScope, "cannot request openid scope for client credentials grant")
	}

	if !client.AreScopesAllowed(ctx, req.Scopes) {
		ctx.Logger().Info("scope not allowed")
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateTokenBindingRequestWithDPOP(ctx, req, client); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	return nil
}

func newClientCredentialsGrantOptions(
	ctx utils.OAuthContext,
	client goidc.Client,
	req utils.TokenRequest,
) (
	goidc.GrantOptions,
	goidc.OAuthError,
) {
	tokenOptions, err := ctx.GetTokenOptions(client, req.Scopes)
	if err != nil {
		return goidc.GrantOptions{}, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, err.Error())
	}

	scopes := req.Scopes
	if scopes == "" {
		scopes = client.Scopes
	}
	return goidc.GrantOptions{
		GrantType:     goidc.GrantClientCredentials,
		GrantedScopes: scopes,
		Subject:       client.ID,
		ClientID:      client.ID,
		TokenOptions:  tokenOptions,
	}, nil
}
