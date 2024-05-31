package token

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
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
		tokenResp, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCodeGrant:
		tokenResp, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshTokenGrant:
		tokenResp, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		tokenResp, err = models.TokenResponse{}, models.NewOAuthError(constants.UnsupportedGrantType, "unsupported grant type")
	}

	return tokenResp, err
}
