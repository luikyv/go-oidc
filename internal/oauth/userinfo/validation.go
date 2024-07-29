package userinfo

import (
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateUserInfoRequest(
	ctx *utils.Context,
	grantSession *goidc.GrantSession,
	token string,
	tokenType goidc.TokenType,
) goidc.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token expired")
	}

	if !utils.ScopesContainsOpenID(grantSession.ActiveScopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid scope")
	}

	return utils.ValidateTokenConfirmation(ctx, token, tokenType, grantSession.TokenConfirmation())
}
