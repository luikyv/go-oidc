package utils

import (
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func HandleUserInfoRequest(ctx Context, token string) (models.GrantSession, error) {

	tokenId, err := getTokenId(ctx, token)
	if err != nil {
		return models.GrantSession{}, err
	}

	grantSession, err := ctx.GrantSessionManager.GetByTokenId(tokenId)
	if err != nil {
		return models.GrantSession{}, err
	}

	if !slices.Contains(grantSession.Scopes, constants.OpenIdScope) {
		return models.GrantSession{}, errors.New("invalid scope")
	}

	return grantSession, nil
}

func getTokenId(ctx Context, token string) (string, error) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSigningAlgorithms())
	if err != nil {
		return token, nil
	}

	if len(parsedToken.Headers) == 0 || parsedToken.Headers[0].KeyID == "" {
		return "", errors.New("invalid header kid")
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
		Issuer: constants.Host,
	}, time.Duration(0)); err != nil {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if claims.ID == "" {
		return "", errors.New("invalid claim jti")
	}

	return claims.ID, nil
}
