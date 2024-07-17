package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type ResultChannel struct {
	Result any
	Err    goidc.OAuthError
}

func JARFromRequestObject(
	ctx *Context,
	reqObject string,
	client *goidc.Client,
) (
	AuthorizationRequest,
	goidc.OAuthError,
) {
	if ctx.JAREncryptionIsEnabled && IsJWE(reqObject) {
		signedReqObject, err := signedRequestObjectFromEncryptedRequestObject(ctx, reqObject, client)
		if err != nil {
			return AuthorizationRequest{}, err
		}
		reqObject = signedReqObject
	}

	if !IsJWS(reqObject) {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "the request object is not a JWS")
	}

	return jarFromSignedRequestObject(ctx, reqObject, client)
}

func signedRequestObjectFromEncryptedRequestObject(
	ctx *Context,
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
	if !ok || jwk.Usage() != string(goidc.KeyUsageEncryption) {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid JWK used for encryption")
	}

	decryptedReqObject, err := encryptedReqObject.Decrypt(jwk.Key())
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	return string(decryptedReqObject), nil
}

func jarFromSignedRequestObject(
	ctx *Context,
	reqObject string,
	client *goidc.Client,
) (
	AuthorizationRequest,
	goidc.OAuthError,
) {
	jarAlgorithms := ctx.JARSignatureAlgorithms
	if client.JARSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JARSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.PublicKey(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key(), &claims, &jarReq); err != nil {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "could not extract claims")
	}

	// Validate that the "exp" claims is present and it's not too far in the future.
	if claims.Expiry == nil || int(time.Until(claims.Expiry.Time()).Seconds()) > ctx.JARLifetimeSecs {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid exp claim")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}

func ValidateDPoPJWT(
	ctx *Context,
	dpopJWT string,
	expectedDPoPClaims DPoPJWTValidationOptions,
) goidc.OAuthError {
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSignatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if len(parsedDPoPJWT.Headers) != 1 {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	if parsedDPoPJWT.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDPoPJWT.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims DPoPJWTClaims
	if err := parsedDPoPJWT.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DPoPLifetimeSecs {
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jti claim")
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid htm claim")
	}

	// The query and fragment components of the "htu" must be ignored.
	// Also, htu should be case-insensitive.
	httpURI, err := URLWithoutParams(strings.ToLower(dpopClaims.HTTPURI))
	if err != nil || !slices.Contains(ctx.Audiences(), httpURI) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid htu claim")
	}

	if expectedDPoPClaims.AccessToken != "" && dpopClaims.AccessTokenHash != HashBase64URLSHA256(expectedDPoPClaims.AccessToken) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid ath claim")
	}

	if expectedDPoPClaims.JWKThumbprint != "" && JWKThumbprint(dpopJWT, ctx.DPoPSignatureAlgorithms) != expectedDPoPClaims.JWKThumbprint {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop")
	}

	return nil
}

// ValidClaims verifies a token and returns its claims.
func ValidClaims(
	ctx *Context,
	token string,
) (
	map[string]any,
	goidc.OAuthError,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.SignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "could not parse the token")
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid header kid")
	}

	keyID := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.PublicKey(keyID)
	if !ok || publicKey.Usage() != string(goidc.KeyUsageSignature) {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey.Key(), &claims, &rawClaims); err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	return rawClaims, nil
}

// TokenID returns the ID of a token.
// If it's a JWT, the ID is the the "jti" claim. Otherwise, the token is considered opaque and its ID is the token itself.
func TokenID(ctx *Context, token string) (string, goidc.OAuthError) {
	if !IsJWS(token) {
		return token, nil
	}

	claims, err := ValidClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenID := claims[string(goidc.ClaimTokenID)]
	if tokenID == nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	return tokenID.(string), nil
}

func RunValidations(
	ctx *Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
	validators ...func(
		ctx *Context,
		params goidc.AuthorizationParameters,
		client *goidc.Client,
	) goidc.OAuthError,
) goidc.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func ProtectedParamsFromForm(ctx *Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.FormData() {
		if strings.HasPrefix(param, goidc.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func ProtectedParamsFromRequestObject(ctx *Context, request string) map[string]any {
	parsedRequest, err := jwt.ParseSigned(request, ctx.JARSignatureAlgorithms)
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
		if strings.HasPrefix(param, goidc.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func EncryptJWT(
	_ *Context,
	jwtString string,
	encryptionJWK goidc.JSONWebKey,
	contentKeyEncryptionAlgorithm jose.ContentEncryption,
) (
	string,
	goidc.OAuthError,
) {
	encrypter, err := jose.NewEncrypter(
		contentKeyEncryptionAlgorithm,
		jose.Recipient{Algorithm: jose.KeyAlgorithm(encryptionJWK.Algorithm()), Key: encryptionJWK.Key(), KeyID: encryptionJWK.KeyID()},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	encryptedUserInfoJWTJWE, err := encrypter.Encrypt([]byte(jwtString))
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	encryptedUserInfoString, err := encryptedUserInfoJWTJWE.CompactSerialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return encryptedUserInfoString, nil
}

func NewGrantSession(grantOptions goidc.GrantOptions, token Token) *goidc.GrantSession {
	timestampNow := goidc.TimestampNow()
	return &goidc.GrantSession{
		ID:                          uuid.New().String(),
		TokenID:                     token.ID,
		JWKThumbprint:               token.JWKThumbprint,
		ClientCertificateThumbprint: token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.TokenLifetimeSecs,
		ActiveScopes:                grantOptions.GrantedScopes,
		GrantOptions:                grantOptions,
	}
}

func NewAuthnSession(authParams goidc.AuthorizationParameters, client *goidc.Client) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:                       uuid.NewString(),
		ClientID:                 client.ID,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       goidc.TimestampNow(),
		Store:                    make(map[string]any),
		AdditionalTokenClaims:    make(map[string]any),
		AdditionalIDTokenClaims:  map[string]any{},
		AdditionalUserInfoClaims: map[string]any{},
	}
}

func RefreshToken() (string, error) {
	return goidc.RandomString(goidc.RefreshTokenLength)
}

func ClientID() (string, error) {
	clientID, err := goidc.RandomString(goidc.DynamicClientIDLength)
	if err != nil {
		return "", err
	}
	return "dc-" + clientID, nil
}

func ClientSecret() (string, error) {
	return goidc.RandomString(goidc.ClientSecretLength)
}

func RegistrationAccessToken() (string, error) {
	return goidc.RandomString(goidc.RegistrationAccessTokenLength)
}

func URLWithQueryParams(redirectURI string, params map[string]string) string {
	parsedURL, _ := url.Parse(redirectURI)
	query := parsedURL.Query()
	for param, value := range params {
		query.Add(param, value)
	}
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func URLWithFragmentParams(redirectURI string, params map[string]string) string {
	parsedURL, _ := url.Parse(redirectURI)
	fragments, _ := url.ParseQuery(parsedURL.Fragment)
	for param, value := range params {
		fragments.Add(param, value)
	}
	parsedURL.Fragment = fragments.Encode()
	return parsedURL.String()
}

func URLWithoutParams(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String(), nil
}

func IsPkceValid(codeVerifier string, codeChallenge string, codeChallengeMethod goidc.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case goidc.CodeChallengeMethodPlain:
		return codeChallenge == codeVerifier
	case goidc.CodeChallengeMethodSHA256:
		return codeChallenge == HashBase64URLSHA256(codeVerifier)
	}

	return false
}

// Return true if all the elements in the slice respect the condition.
func All[T interface{}](slice []T, condition func(T) bool) bool {
	for _, element := range slice {
		if !condition(element) {
			return false
		}
	}

	return true
}

// Return true only if all the elements in values are equal.
func AllEquals[T comparable](values []T) bool {
	if len(values) == 0 {
		return true
	}

	return All(
		values,
		func(value T) bool {
			return value == values[0]
		},
	)
}

func ScopesContainsOpenID(scopes string) bool {
	return slices.Contains(goidc.SplitStringWithSpaces(scopes), goidc.ScopeOpenID.ID)
}

func ScopesContainsOfflineAccess(scopes string) bool {
	return slices.Contains(goidc.SplitStringWithSpaces(scopes), goidc.ScopeOffilineAccess.ID)
}

// JWKThumbprint generates a JWK thumbprint for a valid DPoP JWT.
func JWKThumbprint(dpopJWT string, dpopSigningAlgorithms []jose.SignatureAlgorithm) string {
	parsedDPoPJWT, _ := jwt.ParseSigned(dpopJWT, dpopSigningAlgorithms)
	jkt, _ := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(jkt)
}

func HashBase64URLSHA256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func HashSHA256(s []byte) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func HashSHA1(s []byte) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func HalfHashIDTokenClaim(claimValue string, idTokenAlgorithm jose.SignatureAlgorithm) string {
	var hash hash.Hash
	switch idTokenAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256, jose.HS256:
		hash = sha256.New()
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		hash = sha512.New384()
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		hash = sha512.New()
	default:
		hash = nil
	}

	hash.Write([]byte(claimValue))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

func IsJWS(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)", token)
	return isJWS
}

func IsJWE(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*\\.[\\w-]*\\.[\\w-]*$)", token)
	return isJWS
}

func ComparePublicKeys(k1 any, k2 any) bool {
	key2, ok := k2.(crypto.PublicKey)
	if !ok {
		return false
	}

	switch key1 := k1.(type) {
	case ed25519.PublicKey:
		return key1.Equal(key2)
	case *ecdsa.PublicKey:
		return key1.Equal(key2)
	case *rsa.PublicKey:
		return key1.Equal(key2)
	default:
		return false
	}
}
