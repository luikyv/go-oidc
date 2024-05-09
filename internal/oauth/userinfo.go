package oauth

import (
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleUserInfoRequest(ctx utils.Context, token string) (models.GrantSession, issues.OAuthError) {

	tokenId, oauthErr := getTokenId(ctx, token)
	if oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionManager.GetByTokenId(tokenId)
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid invalid token")
	}

	if !slices.Contains(grantSession.Scopes, constants.OpenIdScope) {
		return models.GrantSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid scope")
	}

	return grantSession, nil
}

func getTokenId(ctx utils.Context, token string) (string, issues.OAuthError) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSigningAlgorithms())
	if err != nil {
		return token, nil
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return "", issues.NewOAuthError(constants.InvalidRequest, "invalid header kid")
	}

	keyId := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.GetPublicKey(keyId)
	if !ok {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	claims := jwt.Claims{}
	if err := parsedToken.Claims(publicKey, &claims); err != nil {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if claims.ID == "" {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return claims.ID, nil
}
