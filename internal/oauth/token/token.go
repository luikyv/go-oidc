package token

import (
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func HandleTokenCreation(
	ctx *utils.Context,
	req utils.TokenRequest,
) (
	tokenResp utils.TokenResponse,
	err error,
) {
	switch req.GrantType {
	case goidc.GrantClientCredentials:
		tokenResp, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case goidc.GrantAuthorizationCode:
		tokenResp, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case goidc.GrantRefreshToken:
		tokenResp, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		tokenResp, err = utils.TokenResponse{}, goidc.NewOAuthError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	return tokenResp, err
}
