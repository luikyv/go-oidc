package token

import (
	"regexp"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func HandleTokenCreation(
	ctx *oidc.Context,
	req tokenRequest,
) (
	tokenResp tokenResponse,
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
		tokenResp, err = tokenResponse{}, oidc.NewError(oidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	return tokenResp, err
}

// TokenID returns the ID of a token.
// If it's a JWT, the ID is the the "jti" claim. Otherwise, the token is considered opaque and its ID is the token itself.
func TokenID(ctx *oidc.Context, token string) (string, oidc.Error) {
	if !IsJWS(token) {
		return token, nil
	}

	claims, err := ValidClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenID := claims[string(goidc.ClaimTokenID)]
	if tokenID == nil {
		return "", oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid token")
	}

	return tokenID.(string), nil
}

// ValidClaims verifies a token and returns its claims.
func ValidClaims(
	ctx *oidc.Context,
	token string,
) (
	map[string]any,
	oidc.Error,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.SignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "could not parse the token")
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid header kid")
	}

	keyID := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.PublicKey(keyID)
	if !ok || publicKey.Use != string(goidc.KeyUsageSignature) {
		return nil, oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.Key, &claims, &rawClaims); err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid token")
	}

	return rawClaims, nil
}

func IsJWS(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)", token)
	return isJWS
}

func IsJWE(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*\\.[\\w-]*\\.[\\w-]*$)", token)
	return isJWS
}
