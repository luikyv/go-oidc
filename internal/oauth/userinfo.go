package oauth

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleUserInfoRequest(ctx utils.Context, token string) (models.GrantSession, models.OAuthError) {

	tokenId, oauthErr := utils.GetTokenId(ctx, token)
	if oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionManager.GetByTokenId(tokenId)
	if err != nil {
		return models.GrantSession{}, models.NewOAuthError(constants.InvalidRequest, "invalid token")
	}

	if grantSession.HasLastTokenExpired() {
		return models.GrantSession{}, models.NewOAuthError(constants.InvalidRequest, "token expired")
	}

	if !unit.ScopesContainsOpenId(grantSession.GrantedScopes) {
		return models.GrantSession{}, models.NewOAuthError(constants.InvalidRequest, "invalid scope")
	}

	return grantSession, nil
}
