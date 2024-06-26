package token

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func HandleTokenCreation(
	ctx utils.Context,
	req utils.TokenRequest,
) (
	tokenResp utils.TokenResponse,
	err error,
) {
	switch req.GrantType {
	case goidc.ClientCredentialsGrant:
		ctx.Logger.Info("handling client_credentials grant type")
		tokenResp, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case goidc.AuthorizationCodeGrant:
		ctx.Logger.Info("handling authorization_code grant type")
		tokenResp, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case goidc.RefreshTokenGrant:
		ctx.Logger.Info("handling refresh_token grant type")
		tokenResp, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		tokenResp, err = utils.TokenResponse{}, goidc.NewOAuthError(goidc.UnsupportedGrantType, "unsupported grant type")
	}

	return tokenResp, err
}
