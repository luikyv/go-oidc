package authorize

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func JARFromRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	authorizationRequest,
	goidc.OAuthError,
) {
	if ctx.JAREncryptionIsEnabled && token.IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncryptedRequestObject(ctx, reqObject, client)
		if err != nil {
			return authorizationRequest{}, err
		}
		reqObject = signedReqObject
	}

	if !token.IsJWS(reqObject) {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "the request object is not a JWS")
	}

	return jarFromSignedRequestObject(ctx, reqObject, client)
}

func signedRequestObjectFromEncryptedRequestObject(
	ctx *oidc.Context,
	reqObject string,
	_ *goidc.Client,
) (
	string,
	goidc.OAuthError,
) {
	encryptedReqObject, err := jose.ParseEncrypted(reqObject, ctx.JARKeyEncryptionAlgorithms(), ctx.JARContentEncryptionAlgorithms)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "could not parse the encrypted request object")
	}

	keyID := encryptedReqObject.Header.KeyID
	if keyID == "" {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid JWE key ID")
	}

	jwk, ok := ctx.PrivateKey(keyID)
	if !ok || jwk.Use != string(goidc.KeyUsageEncryption) {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid JWK used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	return string(decryptedReqObject), nil
}

func jarFromSignedRequestObject(
	ctx *oidc.Context,
	reqObject string,
	client *goidc.Client,
) (
	authorizationRequest,
	goidc.OAuthError,
) {
	jarAlgorithms := ctx.JARSignatureAlgorithms
	if client.JARSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JARSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.PublicKey(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq authorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JARLifetimeSecs {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}
