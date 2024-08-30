package token

import (
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func ValidatePoP(
	ctx *oidc.Context,
	token string,
	tokenType goidc.TokenType,
	confirmation goidc.TokenConfirmation,
) error {
	if err := validateDPoP(ctx, token, tokenType, confirmation); err != nil {
		return err
	}

	return validateTLSPoP(ctx, confirmation)
}

func validateDPoPJWT(
	ctx *oidc.Context,
	dpopJWT string,
	opts dpopValidationOptions,
) error {
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSigAlgs)
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidRequest, "invalid dpop jwt", err)
	}

	if len(parsedDPoPJWT.Headers) != 1 {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid dpop")
	}

	if parsedDPoPJWT.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDPoPJWT.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims dpopClaims
	if err := parsedDPoPJWT.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidRequest, "invalid dpop jwt", err)
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DPoPLifetimeSecs {
		return oidcerr.New(oidcerr.CodeUnauthorizedClient,
			"invalid dpop jwt issuance time")
	}

	if claims.ID == "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpURI, err := urlWithoutParams(strings.ToLower(dpopClaims.HTTPURI))
	if err != nil || !slices.Contains(ctx.Audiences(), httpURI) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid htu claim")
	}

	if opts.accessToken != "" &&
		dpopClaims.AccessTokenHash != hashBase64URLSHA256(opts.accessToken) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid ath claim")
	}

	if opts.jwkThumbprint != "" &&
		jwkThumbprint(dpopJWT, ctx.DPoPSigAlgs) != opts.jwkThumbprint {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid dpop")
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
) error {

	if confirmation.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPoP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not of
			// DPoP type, there is nothing to validate.
			return nil
		}
	}

	dpopJWT, ok := dpopJWT(ctx)
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid DPoP header")
	}

	return validateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{
		accessToken:   token,
		jwkThumbprint: confirmation.JWKThumbprint,
	})
}

func validateTLSPoP(
	ctx *oidc.Context,
	confirmation goidc.TokenConfirmation,
) error {
	if confirmation.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.ClientCert()
	if !ok {
		return oidcerr.New(oidcerr.CodeInvalidToken,
			"the client certificate is required")
	}

	if confirmation.ClientCertificateThumbprint != hashBase64URLSHA256(string(clientCert.Raw)) {
		return oidcerr.New(oidcerr.CodeInvalidToken,
			"invalid client certificate")
	}

	return nil
}

// DPoPJWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func dpopJWT(ctx *oidc.Context) (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDPoPHeader := textproto.CanonicalMIMEHeaderKey(goidc.HeaderDPoP)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Request.Header)

	values := canonicalizedHeaders[canonicalizedDPoPHeader]
	if values == nil || len(values) != 1 {
		return "", false
	}
	return values[0], true
}
