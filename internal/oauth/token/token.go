package token

import (
	"net/http"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleGrantCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	grantSession models.GrantSession,
	err error,
) {

	if err := validateDpopJwtRequest(ctx, req); err != nil {
		return models.GrantSession{}, err
	}

	switch req.GrantType {
	case constants.ClientCredentialsGrant:
		grantSession, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCodeGrant:
		grantSession, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshTokenGrant:
		grantSession, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		grantSession, err = models.GrantSession{}, issues.NewOAuthError(constants.UnsupportedGrantType, "unsupported grant type")
	}

	return grantSession, err
}

func validateDpopJwtRequest(ctx utils.Context, req models.TokenRequest) issues.OAuthError {
	if req.DpopJwt != "" {
		return utils.ValidateDpopJwt(req.DpopJwt, models.DpopClaims{
			HttpMethod: http.MethodPost,
			HttpUri:    ctx.Host + string(constants.TokenEndpoint),
		})
	}

	return nil
}
