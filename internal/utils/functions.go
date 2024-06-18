package utils

import (
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type ResultChannel struct {
	Result any
	Err    models.OAuthError
}

func ExtractJarFromRequestObject(
	ctx Context,
	reqObject string,
	client models.Client,
) (
	models.AuthorizationRequest,
	models.OAuthError,
) {
	if ctx.JarEncryptionIsEnabled && unit.IsJwe(reqObject) {
		signedReqObject, err := extractSignedRequestObjectFromEncryptedRequestObject(ctx, reqObject, client)
		if err != nil {
			return models.AuthorizationRequest{}, err
		}
		reqObject = signedReqObject
	}

	if !unit.IsJws(reqObject) {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidRequest, "the request object is not a JWS")
	}

	return extractJarFromSignedRequestObject(ctx, reqObject, client)
}

func extractSignedRequestObjectFromEncryptedRequestObject(
	ctx Context,
	reqObject string,
	_ models.Client,
) (
	string,
	models.OAuthError,
) {
	encryptedReqObject, err := jose.ParseEncrypted(reqObject, ctx.GetJarKeyEncryptionAlgorithms(), ctx.JarContentEncryptionAlgorithms)
	if err != nil {
		return "", models.NewOAuthError(constants.InvalidResquestObject, "could not parse the encrypted request object")
	}

	keyId := encryptedReqObject.Header.KeyID
	if keyId == "" {
		return "", models.NewOAuthError(constants.InvalidResquestObject, "invalid JWE key ID")
	}

	jwk, ok := ctx.GetPrivateKey(keyId)
	if !ok || jwk.Use != string(constants.KeyEncryptionUsage) {
		return "", models.NewOAuthError(constants.InvalidResquestObject, "invalid JWK used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key)
	if err != nil {
		return "", models.NewOAuthError(constants.InvalidResquestObject, err.Error())
	}

	return string(decryptedReqObject), nil
}

func extractJarFromSignedRequestObject(
	ctx Context,
	reqObject string,
	client models.Client,
) (
	models.AuthorizationRequest,
	models.OAuthError,
) {
	jarAlgorithms := ctx.JarSignatureAlgorithms
	if client.JarSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JarSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.GetJwk(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JarLifetimeSecs {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}

func ValidateDpopJwt(
	ctx Context,
	dpopJwt string,
	expectedDpopClaims models.DpopJwtValidationOptions,
) models.OAuthError {
	parsedDpopJwt, err := jwt.ParseSigned(dpopJwt, ctx.DpopSignatureAlgorithms)
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if len(parsedDpopJwt.Headers) != 1 {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if parsedDpopJwt.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDpopJwt.Headers[0].JSONWebKey
	if jwk == nil || !jwk.IsPublic() {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims models.DpopJwtClaims
	if err := parsedDpopJwt.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DpopLifetimeSecs {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HttpMethod != ctx.GetRequestMethod() {
		return models.NewOAuthError(constants.InvalidRequest, "invalid htm claim")
	}

	httpUri, err := unit.GetUrlWithoutParams(dpopClaims.HttpUri)
	// The query and fragment components of the "htu" must be ignored.
	if err != nil || httpUri != ctx.GetRequestUrl() {
		return models.NewOAuthError(constants.InvalidRequest, "invalid htu claim")
	}

	if expectedDpopClaims.AccessToken != "" && dpopClaims.AccessTokenHash != unit.CreateSha256Hash(expectedDpopClaims.AccessToken) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid ath claim")
	}

	if expectedDpopClaims.JwkThumbprint != "" && unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms) != expectedDpopClaims.JwkThumbprint {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	return nil
}

func GetValidTokenClaims(
	ctx Context,
	token string,
) (
	map[string]any,
	models.OAuthError,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, models.NewOAuthError(constants.InvalidRequest, "could not parse the token")
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, models.NewOAuthError(constants.InvalidRequest, "invalid header kid")
	}

	keyId := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.GetPublicKey(keyId)
	if !ok || publicKey.Use != string(constants.KeySignatureUsage) {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey, &claims, &rawClaims); err != nil {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return rawClaims, nil
}

func GetTokenId(ctx Context, token string) (string, models.OAuthError) {
	if !unit.IsJws(token) {
		return token, nil
	}

	claims, err := GetValidTokenClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenId := claims[string(constants.TokenIdClaim)]
	if tokenId == nil {
		return "", models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return tokenId.(string), nil
}

func RunValidations(
	ctx Context,
	params models.AuthorizationParameters,
	client models.Client,
	validators ...func(
		ctx Context,
		params models.AuthorizationParameters,
		client models.Client,
	) models.OAuthError,
) models.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func ExtractProtectedParamsFromForm(ctx Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.GetFormData() {
		if strings.HasPrefix(param, constants.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func ExtractProtectedParamsFromRequestObject(ctx Context, request string) map[string]any {
	parsedRequest, err := jwt.ParseSigned(request, ctx.JarSignatureAlgorithms)
	if err != nil {
		return map[string]any{}
	}

	var claims map[string]any
	err = parsedRequest.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return map[string]any{}
	}

	protectedParams := make(map[string]any)
	for param, value := range claims {
		if strings.HasPrefix(param, constants.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func EncryptJwt(
	_ Context,
	jwtString string,
	encryptionJwk jose.JSONWebKey,
	contentKeyEncryptionAlgorithm jose.ContentEncryption,
) (
	string,
	models.OAuthError,
) {
	encrypter, err := jose.NewEncrypter(
		contentKeyEncryptionAlgorithm,
		jose.Recipient{Algorithm: jose.KeyAlgorithm(encryptionJwk.Algorithm), Key: encryptionJwk.Key, KeyID: encryptionJwk.KeyID},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	encryptedUserInfoJwtJwe, err := encrypter.Encrypt([]byte(jwtString))
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	encryptedUserInfoString, err := encryptedUserInfoJwtJwe.CompactSerialize()
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	return encryptedUserInfoString, nil
}
