package token

import (
	"net/http"

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
	if err := validateDpopJwtRequest(ctx, req); err != nil {
		return models.TokenResponse{}, err
	}

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

func validateDpopJwtRequest(ctx utils.Context, req models.TokenRequest) models.OAuthError {

	if req.DpopJwt == "" && ctx.DpopIsRequired {
		return models.NewOAuthError(constants.InvalidRequest, "missing dpop header")
	}

	if req.DpopJwt == "" || !ctx.DpopIsEnabled {
		// If DPoP is not enabled, we just ignore the DPoP header.
		return nil
	}

	return utils.ValidateDpopJwt(ctx, req.DpopJwt, models.DpopClaims{
		HttpMethod: http.MethodPost,
		HttpUri:    ctx.Host + string(constants.TokenEndpoint),
	})
}
