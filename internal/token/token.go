package token

import (
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ExtractID returns the ID of a token.
//
// If it's a JWT, the ID is the the "jti" claim. Otherwise, the token is
// considered opaque and its ID is the token itself.
func ExtractID(ctx *oidc.Context, token string) (string, error) {
	if !jwtutil.IsJWS(token) {
		return token, nil
	}

	claims, err := ValidClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenID := claims[string(goidc.ClaimTokenID)]
	if tokenID == nil {
		return "", oidcerr.New(oidcerr.CodeAccessDenied, "invalid token")
	}

	return tokenID.(string), nil
}

// ValidClaims verifies a token and returns its claims.
func ValidClaims(
	ctx *oidc.Context,
	token string,
) (
	map[string]any,
	error,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.SignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not parse the token", err)
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid header kid")
	}

	keyID := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.PublicKey(keyID)
	if !ok || publicKey.Use != string(goidc.KeyUsageSignature) {
		return nil, oidcerr.New(oidcerr.CodeAccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.Key, &claims, &rawClaims); err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeAccessDenied,
			"invalid token", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeAccessDenied, "invalid token", err)
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
	switch req.GrantType {
	case goidc.GrantClientCredentials:
		return generateClientCredentialsGrant(ctx, req)
	case goidc.GrantAuthorizationCode:
		return generateAuthorizationCodeGrant(ctx, req)
	case goidc.GrantRefreshToken:
		return generateRefreshTokenGrant(ctx, req)
	default:
		return response{}, oidcerr.New(oidcerr.CodeUnsupportedGrantType,
			"unsupported grant type")
	}
}
