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
) oidc.Error {
	if err := validateDPoP(ctx, token, tokenType, confirmation); err != nil {
		return err
	}

	return validateTLSPoP(ctx, confirmation)
}

func ValidateDPoPJWT(
	ctx *oidc.Context,
	dpopJWT string,
	expectedDPoPClaims dpopValidationOptions,
) oidc.Error {
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, ctx.DPoP.SignatureAlgorithms)
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if len(parsedDPoPJWT.Headers) != 1 {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if parsedDPoPJWT.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDPoPJWT.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims dpopClaims
	if err := parsedDPoPJWT.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DPoP.LifetimeSecs {
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpURI, err := urlWithoutParams(strings.ToLower(dpopClaims.HTTPURI))
	if err != nil || !slices.Contains(ctx.Audiences(), httpURI) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid htu claim")
	}

	if expectedDPoPClaims.AccessToken != "" && dpopClaims.AccessTokenHash != hashBase64URLSHA256(expectedDPoPClaims.AccessToken) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid ath claim")
	}

	if expectedDPoPClaims.JWKThumbprint != "" && jwkThumbprint(dpopJWT, ctx.DPoP.SignatureAlgorithms) != expectedDPoPClaims.JWKThumbprint {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid dpop")
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
) oidc.Error {

	if confirmation.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPoP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{
		AccessToken:   token,
		JWKThumbprint: confirmation.JWKThumbprint,
	})
}

func validateTLSPoP(
	ctx *oidc.Context,
	confirmation goidc.TokenConfirmation,
) oidc.Error {
	if confirmation.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.ClientCertificate()
	if !ok {
		return oidc.NewError(oidc.ErrorCodeInvalidToken, "the client certificate is required")
	}

	if confirmation.ClientCertificateThumbprint != hashBase64URLSHA256(string(clientCert.Raw)) {
		return oidc.NewError(oidc.ErrorCodeInvalidToken, "invalid client certificate")
	}

	return nil
}
