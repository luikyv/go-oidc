package authorize

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func shouldUseJAR(
	ctx *oidc.Context,
	req goidc.AuthorizationParameters,
	c *goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JARIsRequired ||
		(ctx.JARIsEnabled && (req.RequestObject != "" || c.JARSigAlg != ""))
}

func jarFromRequestObject(
	ctx *oidc.Context,
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

	if !jwtutil.IsJWS(reqObject) {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the request object is not a JWS")
	}

	return jarFromSignedRequestObject(ctx, reqObject, c)
}

func signedRequestObjectFromEncrypted(
	ctx *oidc.Context,
	reqObject string,
	_ *goidc.Client,
) (
	string,
	error,
) {
	encryptedReqObject, err := jose.ParseEncrypted(
		reqObject,
		ctx.JARKeyEncAlgs(),
		ctx.JARContentEncAlgs,
	)
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"could not parse the encrypted request object", err)
	}

	keyID := encryptedReqObject.Header.KeyID
	if keyID == "" {
		return "", goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"invalid jwe key ID")
	}

	jwk, ok := ctx.PrivateKey(keyID)
	if !ok || jwk.Use != string(goidc.KeyUsageEncryption) {
		return "", goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"invalid jwk used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key)
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"could not decrypt the request object", err)
	}

	return string(decryptedReqObject), nil
}

func jarFromSignedRequestObject(
	ctx *oidc.Context,
	reqObject string,
	c *goidc.Client,
) (
	request,
	error,
) {
	jarAlgorithms := ctx.JARSigAlgs
	if c.JARSigAlg != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{c.JARSigAlg}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"invalid request object", err)
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := clientutil.JWKByKeyID(ctx, c, parsedToken.Headers[0].KeyID)
	if err != nil {
		return request{}, goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"could not fetch the client public key", err)
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"could not extract claims from the request object", err)
	}

	validFrom := timeutil.Now()
	if claims.IssuedAt != nil {
		validFrom = claims.IssuedAt.Time()
	}
	// The claim 'nbf' required for FAPI 2.0.
	if ctx.Profile == goidc.ProfileFAPI2 {
		if claims.NotBefore == nil {
			return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
				"claim 'nbf' is required in the request object")
		}
		validFrom = claims.NotBefore.Time().UTC()
	}

	if claims.Expiry == nil {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"claim 'exp' is required in the request object")
	}

	// Validate that the "exp" claims is present and it's not far in the future.
	secsToExpiry := int(claims.Expiry.Time().Sub(validFrom).Seconds())
	if secsToExpiry > ctx.JARLifetimeSecs {
		return request{}, goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"invalid exp claim in the request object")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(ctx.JARLeewayTimeSecs)*time.Second)
	if err != nil {
		return request{}, goidc.Errorf(goidc.ErrorCodeInvalidResquestObject,
			"the request object contains invalid claims", err)
	}

	return jarReq, nil
}
