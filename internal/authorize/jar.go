package authorize

import (
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func shouldUseJARDuringPAR(
	ctx oidc.Context,
	req goidc.AuthorizationParameters,
	c *goidc.Client,
) bool {
	if !ctx.JARIsEnabled {
		return false
	}
	return ctx.JARIsRequired || c.JARIsRequired || req.RequestObject != ""
}

func shouldUseJAR(
	ctx oidc.Context,
	req goidc.AuthorizationParameters,
	c *goidc.Client,
) bool {
	if !ctx.JARIsEnabled {
		return false
	}

	// JAR was informed either by value or reference.
	jarWasInformed := req.RequestObject != "" || (ctx.JARByReferenceIsEnabled && req.RequestURI != "")
	return ctx.JARIsRequired || c.JARIsRequired || jarWasInformed
}

func jarFromRequestURI(
	ctx oidc.Context,
	reqURI string,
	client *goidc.Client,
) (
	request,
	error,
) {
	httpClient := ctx.HTTPClient()
	resp, err := httpClient.Get(reqURI)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"invalid request uri", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"invalid request uri", err)
	}

	reqObject, err := io.ReadAll(resp.Body)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"invalid request uri", err)
	}

	return jarFromRequestObject(ctx, string(reqObject), client)
}

func jarFromRequestObject(
	ctx oidc.Context,
	reqObject string,
	c *goidc.Client,
) (
	request,
	error,
) {
	if ctx.JAREncIsEnabled && jwtutil.IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncrypted(ctx, reqObject, c)
		if err != nil {
			return request{}, err
		}
		reqObject = signedReqObject
	}

	if jwtutil.IsUnsignedJWT(reqObject) {
		return jarFromUnsignedRequestObject(ctx, reqObject, c)
	}

	return jarFromSignedRequestObject(ctx, reqObject, c)
}

func signedRequestObjectFromEncrypted(
	ctx oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	string,
	error,
) {

	contentEncAlgs := ctx.JARContentEncAlgs
	if client.JARContentEncAlg != "" {
		contentEncAlgs = []jose.ContentEncryption{client.JARContentEncAlg}
	}
	jws, err := ctx.Decrypt(reqObject, ctx.JARKeyEncAlgs, contentEncAlgs)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not parse the encrypted request object", err)
	}

	return jws, nil
}

func jarFromUnsignedRequestObject(
	ctx oidc.Context,
	reqObject string,
	c *goidc.Client,
) (
	request,
	error,
) {
	jarAlgorithms := jarAlgorithms(ctx, c)
	parsedJWT, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not parse the request object", err)
	}

	var jarReq request
	if err := parsedJWT.UnsafeClaimsWithoutVerification(&jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not extract claims from the request object", err)
	}

	return jarReq, nil
}

func jarFromSignedRequestObject(
	ctx oidc.Context,
	reqObject string,
	c *goidc.Client,
) (
	request,
	error,
) {
	jarAlgorithms := jarAlgorithms(ctx, c)
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"invalid request object", err)
	}

	if len(parsedToken.Headers) != 1 {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "invalid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := clientutil.JWKMatchingHeader(ctx, c, parsedToken.Headers[0])
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not fetch the client public key", err)
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not extract claims from the request object", err)
	}

	if err := validateClaims(ctx, claims, c); err != nil {
		return request{}, err
	}

	return jarReq, nil
}

func jarAlgorithms(ctx oidc.Context, client *goidc.Client) []jose.SignatureAlgorithm {
	jarAlgorithms := ctx.JARSigAlgs
	if client.JARSigAlg != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JARSigAlg}
	}
	return jarAlgorithms
}

func validateClaims(
	ctx oidc.Context,
	claims jwt.Claims,
	client *goidc.Client,
) error {

	if ctx.Profile.IsFAPI() {

		if claims.NotBefore == nil {
			return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
				"claim 'nbf' is required in the request object")
		}

		if claims.NotBefore.Time().Before(timeutil.Now().Add(-1 * time.Hour)) {
			return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
				"claim 'nbf' is too far in the past")
		}

		if claims.Expiry == nil {
			return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
				"claim 'exp' is required in the request object")
		}

		if claims.Expiry.Time().After(timeutil.Now().Add(1 * time.Hour)) {
			return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
				"claim 'exp' is too far in the future")
		}
	}

	if claims.ID != "" {
		if err := ctx.CheckJTI(claims.ID); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
				"invalid jti claim", err)
		}
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"the request object contains invalid claims", err)
	}

	return nil
}
