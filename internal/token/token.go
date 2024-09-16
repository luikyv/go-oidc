package token

import (
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ExtractID returns the ID of a token.
// If it's a JWT, the ID is the the "jti" claim. Otherwise, the token is
// considered opaque and its ID is the token itself.
func ExtractID(ctx *oidc.Context, token string) (string, error) {
	if !jwtutil.IsJWS(token) {
		return token, nil
	}

	claims, err := validClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenID := claims[string(goidc.ClaimTokenID)]
	if tokenID == nil {
		return "", goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	return tokenID.(string), nil
}

// validClaims verifies a token and returns its claims.
func validClaims(
	ctx *oidc.Context,
	token string,
) (
	map[string]any,
	error,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.SigAlgs())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, goidc.Errorf(goidc.ErrorCodeInvalidRequest,
			"could not parse the token", err)
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid header kid")
	}

	keyID := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.PublicKey(keyID)
	if !ok || publicKey.Use != string(goidc.KeyUsageSignature) {
		return nil, goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.Key, &claims, &rawClaims); err != nil {
		return nil, goidc.Errorf(goidc.ErrorCodeAccessDenied,
			"invalid token", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, goidc.Errorf(goidc.ErrorCodeAccessDenied, "invalid token", err)
	}

	return rawClaims, nil
}

func generateGrant(
	ctx *oidc.Context,
	req request,
) (
	tokenResp response,
	err error,
) {
	switch req.grantType {
	case goidc.GrantClientCredentials:
		return generateClientCredentialsGrant(ctx, req)
	case goidc.GrantAuthorizationCode:
		return generateAuthorizationCodeGrant(ctx, req)
	case goidc.GrantRefreshToken:
		return generateRefreshTokenGrant(ctx, req)
	default:
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType,
			"unsupported grant type")
	}
}
