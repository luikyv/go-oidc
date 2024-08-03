package userinfo

import (
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateUserInfoRequest(
	ctx *utils.Context,
	grantSession *goidc.GrantSession,
	accessToken string,
	tokenType goidc.TokenType,
) goidc.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token expired")
	}

	if !goidc.ScopesContainsOpenID(grantSession.ActiveScopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid scope")
	}

	return token.ValidatePoP(ctx, accessToken, tokenType, grantSession.TokenConfirmation())
}
