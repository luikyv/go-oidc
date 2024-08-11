package authorize

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func jarFromRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	Request,
	oidc.Error,
) {
	if ctx.JAREncryptionIsEnabled && token.IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncrypted(ctx, reqObject, client)
		if err != nil {
			return Request{}, err
		}
		reqObject = signedReqObject
	}

	if !token.IsJWS(reqObject) {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "the request object is not a JWS")
	}

	return jarFromSignedRequestObject(ctx, reqObject, client)
}

func signedRequestObjectFromEncrypted(
	ctx *oidc.Context,
	reqObject string,
	_ *goidc.Client,
) (
	string,
	oidc.Error,
) {
	encryptedReqObject, err := jose.ParseEncrypted(reqObject, ctx.JARKeyEncryptionAlgorithms(), ctx.JARContentEncryptionAlgorithms)
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "could not parse the encrypted request object")
	}

	keyID := encryptedReqObject.Header.KeyID
	if keyID == "" {
		return "", oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid JWE key ID")
	}

	jwk, ok := ctx.PrivateKey(keyID)
	if !ok || jwk.Use != string(goidc.KeyUsageEncryption) {
		return "", oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid JWK used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key)
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	return string(decryptedReqObject), nil
}

func jarFromSignedRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	Request,
	oidc.Error,
) {
	jarAlgorithms := ctx.JARSignatureAlgorithms
	if client.JARSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JARSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.PublicKey(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq Request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int64(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JARLifetimeSecs {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}