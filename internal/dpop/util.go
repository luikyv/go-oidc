package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
}

type Claims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

// JWKThumbprint generates a JWK thumbprint for a valid DPoP JWT.
func JWKThumbprint(dpopJWT string, algs []jose.SignatureAlgorithm) string {
	// TODO: handle the error
	parsedDPoPJWT, _ := jwt.ParseSigned(dpopJWT, algs)
	jkt, _ := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(jkt)
}

// JWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func JWT(ctx *oidc.Context) (string, bool) {
	// To access the dpop jwts from the field Header, we need to use the
	// canonical version of the header "DPoP" which is "Dpop".
	dpopJWTs := ctx.Request.Header[http.CanonicalHeaderKey(goidc.HeaderDPoP)]
	if len(dpopJWTs) != 1 {
		return "", false
	}
	return dpopJWTs[0], true
}

func ValidateJWT(
	ctx *oidc.Context,
	dpopJWT string,
	opts ValidationOptions,
) error {
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSigAlgs)
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "invalid dpop jwt", err)
	}

	if len(parsedDPoPJWT.Headers) != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if parsedDPoPJWT.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid typ header, it should be dpop+jwt")
	}

	jwk := parsedDPoPJWT.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims Claims
	if err := parsedDPoPJWT.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "invalid dpop jwt", err)
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DPoPLifetimeSecs {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient,
			"invalid dpop jwt issuance time")
	}

	if claims.ID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpURI, err := urlWithoutParams(strings.ToLower(dpopClaims.HTTPURI))
	if err != nil || !slices.Contains(ctx.Audiences(), httpURI) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid htu claim")
	}

	if opts.AccessToken != "" &&
		dpopClaims.AccessTokenHash != hashBase64URLSHA256(opts.AccessToken) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid ath claim")
	}

	if opts.JWKThumbprint != "" &&
		JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs) != opts.JWKThumbprint {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(ctx.DPoPLeewayTimeSecs)*time.Second)
	if err != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
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

func hashBase64URLSHA256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
