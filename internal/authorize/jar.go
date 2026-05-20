package authorize

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("could not fetch the request object from request_uri: %w", err))
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("request_uri returned HTTP status %d", resp.StatusCode))
	}

	reqObject, err := io.ReadAll(resp.Body)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("could not read the request object from request_uri: %w", err))
	}

	return jarFromRequestObject(ctx, string(reqObject), client)
}

func jarFromRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client) (request, error) {
	if ctx.JAREncIsEnabled && joseutil.IsJWE(reqObject) {
		contentEncAlgs := ctx.JARContentEncAlgs
		if c.JARContentEncAlg != "" && slices.Contains(ctx.JARContentEncAlgs, c.JARContentEncAlg) {
			contentEncAlgs = []goidc.ContentEncryptionAlgorithm{c.JARContentEncAlg}
		}
		jws, err := ctx.Decrypt(reqObject, ctx.JARKeyEncAlgs, contentEncAlgs)
		if err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
				"invalid request object", fmt.Errorf("could not decrypt the encrypted request object: %w", err))
		}
		reqObject = jws
	}

	jarAlgorithms := ctx.JARSigAlgs
	if c.JARSigAlg != "" && slices.Contains(ctx.JARSigAlgs, c.JARSigAlg) {
		jarAlgorithms = []goidc.SignatureAlgorithm{c.JARSigAlg}
	}

	if slices.Contains(ctx.JARSigAlgs, goidc.None) && joseutil.IsUnsignedJWT(reqObject) {
		parsedJWT, err := jwt.ParseSigned(reqObject, jarAlgorithms)
		if err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				fmt.Errorf("could not parse the unsigned request object: %w", err))
		}

		var jarReq request
		if err := parsedJWT.UnsafeClaimsWithoutVerification(&jarReq); err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				fmt.Errorf("could not extract claims from the unsigned request object: %w", err))
		}

		return jarReq, nil
	}

	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object", fmt.Errorf("could not parse the request object: %w", err))
	}

	if len(parsedToken.Headers) != 1 {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
			errors.New("the request object must contain exactly one JOSE header"))
	}

	// Verify that the key ID belongs to the client.
	jwk, err := client.JWKMatchingHeader(ctx, c, parsedToken.Headers[0])
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"invalid request object", fmt.Errorf("could not resolve the client public key for the request object header: %w", err))
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject,
			"invalid request object", fmt.Errorf("could not extract claims from the request object: %w", err))
	}

	if ctx.Profile.IsFAPI() {
		if claims.NotBefore == nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				errors.New("claim 'nbf' is required in the request object"))
		}

		if claims.NotBefore.Time().Before(timeutil.Now().Add(-1 * time.Hour)) {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				errors.New("claim 'nbf' is too far in the past"))
		}

		if claims.Expiry == nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				errors.New("claim 'exp' is required in the request object"))
		}

		if claims.Expiry.Time().After(timeutil.Now().Add(1 * time.Hour)) {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				errors.New("claim 'exp' is too far in the future"))
		}
	}

	if claims.ID != "" {
		if err := ctx.CheckJTI(claims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
				fmt.Errorf("could not validate the request object jti: %w", err))
		}
	}

	if claims.Subject != "" {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object",
			errors.New("claim 'sub' is not allowed in the request object"))
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Issuer()},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "the request object contains invalid claims", err)
	}

	return jarReq, nil
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
