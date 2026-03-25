package authorize

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func jarFromRequestURI(ctx oidc.Context, reqURI string, client *goidc.Client) (request, error) {
	resp, err := ctx.HTTPClient().Get(reqURI)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request uri", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request uri",
			fmt.Errorf("request uri returned status code: %d", resp.StatusCode))
	}

	reqObject, err := io.ReadAll(resp.Body)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request uri", err)
	}

	return jarFromRequestObject(ctx, string(reqObject), client)
}

func jarFromRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
	if ctx.JAREncIsEnabled && joseutil.IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncrypted(ctx, reqObject, c)
		if err != nil {
			return request{}, err
		}
		reqObject = signedReqObject
	}

	if joseutil.IsUnsignedJWT(reqObject) {
		return jarFromUnsignedRequestObject(ctx, reqObject, c)
	}

	return jarFromSignedRequestObject(ctx, reqObject, c)
}

func signedRequestObjectFromEncrypted(ctx oidc.Context, reqObject string, client *goidc.Client) (string, error) {

	contentEncAlgs := ctx.JARContentEncAlgs
	if client.JARContentEncAlg != "" {
		contentEncAlgs = []goidc.ContentEncryptionAlgorithm{client.JARContentEncAlg}
	}
	jws, err := ctx.Decrypt(reqObject, ctx.JARKeyEncAlgs, contentEncAlgs)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"could not parse the encrypted request object", err)
	}

	return jws, nil
}

// TODO: Does this really work?
func jarFromUnsignedRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
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

func jarFromSignedRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
	jarAlgorithms := jarAlgorithms(ctx, c)
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object", err)
	}

	if len(parsedToken.Headers) != 1 {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "invalid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := client.JWKMatchingHeader(ctx, c, parsedToken.Headers[0])
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

func jarAlgorithms(ctx oidc.Context, client *goidc.Client) []goidc.SignatureAlgorithm {
	jarAlgorithms := ctx.JARSigAlgs
	if client.JARSigAlg != "" {
		jarAlgorithms = []goidc.SignatureAlgorithm{client.JARSigAlg}
	}
	return jarAlgorithms
}

func validateClaims(ctx oidc.Context, claims jwt.Claims, client *goidc.Client) error {

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
			return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid jti claim", err)
		}
	}

	if claims.Subject != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "subject is not allowed in the request object")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Issuer()},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "the request object contains invalid claims", err)
	}

	return nil
}

// jarTrustChain extracts the trust_chain header or claim from a JAR request object.
// Returns nil if parsing fails or the value is absent/malformed.
func jarTrustChain(reqObject string, sigAlgs []goidc.SignatureAlgorithm) []string {
	parsed, err := jwt.ParseSigned(reqObject, sigAlgs)
	if err != nil || len(parsed.Headers) == 0 {
		return nil
	}

	raw, ok := parsed.Headers[0].ExtraHeaders["trust_chain"]
	if !ok {
		var claims struct {
			TrustChain []string `json:"trust_chain"`
		}
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return nil
		}
		return claims.TrustChain
	}

	items, ok := raw.([]any)
	if !ok {
		return nil
	}

	chain := make([]string, 0, len(items))
	for _, v := range items {
		s, ok := v.(string)
		if !ok {
			return nil
		}
		chain = append(chain, s)
	}

	return chain
}
