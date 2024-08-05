package token

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func ValidatePoP(
	ctx *oidc.Context,
	token string,
	tokenType goidc.TokenType,
	confirmation goidc.TokenConfirmation,
) goidc.OAuthError {
	if err := validateDPoP(ctx, token, tokenType, confirmation); err != nil {
		return err
	}

	return validateTLSPoP(ctx, confirmation)
}

func ValidateDPoPJWT(
	ctx *oidc.Context,
	dpopJWT string,
	expectedDPoPClaims DPoPJWTValidationOptions,
) goidc.OAuthError {
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSignatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if len(parsedDPoPJWT.Headers) != 1 {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if parsedDPoPJWT.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDPoPJWT.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims dpopJWTClaims
	if err := parsedDPoPJWT.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DPoPLifetimeSecs {
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpURI, err := urlWithoutParams(strings.ToLower(dpopClaims.HTTPURI))
	if err != nil || !slices.Contains(ctx.Audiences(), httpURI) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid htu claim")
	}

	if expectedDPoPClaims.AccessToken != "" && dpopClaims.AccessTokenHash != hashBase64URLSHA256(expectedDPoPClaims.AccessToken) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid ath claim")
	}

	if expectedDPoPClaims.JWKThumbprint != "" && jwkThumbprint(dpopJWT, ctx.DPoPSignatureAlgorithms) != expectedDPoPClaims.JWKThumbprint {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	return nil
}

func urlWithoutParams(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String(), nil
}

func validateDPoP(
	ctx *oidc.Context,
	token string,
	tokenType goidc.TokenType,
	confirmation goidc.TokenConfirmation,
) goidc.OAuthError {

	if confirmation.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPoP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, DPoPJWTValidationOptions{
		AccessToken:   token,
		JWKThumbprint: confirmation.JWKThumbprint,
	})
}

func validateTLSPoP(
	ctx *oidc.Context,
	confirmation goidc.TokenConfirmation,
) goidc.OAuthError {
	if confirmation.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.ClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "the client certificate is required")
	}

	if confirmation.ClientCertificateThumbprint != hashBase64URLSHA256(string(clientCert.Raw)) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "invalid client certificate")
	}

	return nil
}
