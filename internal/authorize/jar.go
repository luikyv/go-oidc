package authorize

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func shouldUseJAR(
	ctx *oidc.Context,
	req goidc.AuthorizationParameters,
	client *goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JAR.IsRequired ||
		(ctx.JAR.IsEnabled && (req.RequestObject != "" || client.JARSigAlg != ""))
}

func jarFromRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	request,
	error,
) {
	if ctx.JAR.EncIsEnabled && token.IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncrypted(ctx, reqObject, client)
		if err != nil {
			return request{}, err
		}
		reqObject = signedReqObject
	}

	if !token.IsJWS(reqObject) {
		return request{}, oidcerr.New(oidcerr.CodeInvalidRequest, "the request object is not a JWS")
	}

	return jarFromSignedRequestObject(ctx, reqObject, client)
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
		ctx.JAR.ContentEncAlgs,
	)
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"could not parse the encrypted request object")
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
		return "", oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"could not decrypt the request object")
	}

	return string(decryptedReqObject), nil
}

func jarFromSignedRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	request,
	error,
) {
	jarAlgorithms := ctx.JAR.SigAlgs
	if client.JARSigAlg != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JARSigAlg}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"invalid request object")
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.PublicKey(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"could not fetch the client public key")
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JAR.LifetimeSecs {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return request{}, oidcerr.New(oidcerr.CodeInvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}
