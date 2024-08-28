package authorize

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
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
		return request{}, oidcerr.New(oidcerr.CodeInvalidRequest, "the request object is not a JWS")
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
		ctx.JARKeyEncryptionAlgorithms(),
		ctx.JARContentEncAlgs,
	)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
			"could not parse the encrypted request object", err)
	}

	keyID := encryptedReqObject.Header.KeyID
	if keyID == "" {
		return "", oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"invalid jwe key ID")
	}

	jwk, ok := ctx.PrivateKey(keyID)
	if !ok || jwk.Use != string(goidc.KeyUsageEncryption) {
		return "", oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"invalid jwk used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
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
		return request{}, oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
			"invalid request object", err)
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, err := clientutil.JWKByKeyID(c, parsedToken.Headers[0].KeyID)
	if err != nil {
		return request{}, oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
			"could not fetch the client public key", err)
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
			"could not extract claims from the request object", err)
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JARLifetimeSecs {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"invalid exp claim in the request object")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return request{}, oidcerr.Errorf(oidcerr.CodeInvalidResquestObject,
			"the request object contains invalid claims", err)
	}

	return jarReq, nil
}
