package token

import (
	"github.com/luikymagno/goidc/internal/constants"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/utils"
)

func HandleTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	tokenResp models.TokenResponse,
	err error,
) {
	switch req.GrantType {
	case constants.ClientCredentialsGrant:
		ctx.Logger.Info("handling client_credentials grant type")
		tokenResp, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCodeGrant:
		ctx.Logger.Info("handling authorization_code grant type")
		tokenResp, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshTokenGrant:
		ctx.Logger.Info("handling refresh_token grant type")
		tokenResp, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		tokenResp, err = models.TokenResponse{}, models.NewOAuthError(constants.UnsupportedGrantType, "unsupported grant type")
	}

	return tokenResp, err
}
