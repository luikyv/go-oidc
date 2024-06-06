package unit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func GenerateRandomString(minLength int, maxLength int) string {

	length := minLength + rand.Intn(maxLength-minLength+1) // minLength >= length <= maxLength
	randomStringInBytes := make([]byte, length)
	charSetSize := len(constants.Charset)
	for i := range randomStringInBytes {
		// Set a random character to randomStringInBytes[i]
		randomStringInBytes[i] = constants.Charset[rand.Intn(charSetSize)]
	}

	return string(randomStringInBytes)
}

func GenerateCallbackId() string {
	return GenerateRandomString(constants.CallbackIdLength, constants.CallbackIdLength)
}

func GenerateRequestUri() string {
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", GenerateRandomString(constants.RequestUriLength, constants.RequestUriLength))
}

func GenerateAuthorizationCode() string {
	return GenerateRandomString(constants.AuthorizationCodeLength, constants.AuthorizationCodeLength)
}

func GenerateRefreshToken() string {
	return GenerateRandomString(constants.RefreshTokenLength, constants.RefreshTokenLength)
}

func GenerateClientId() string {
	return "dc-" + GenerateRandomString(constants.DynamicClientIdLength, constants.DynamicClientIdLength)
}

func GenerateClientSecret() string {
	return GenerateRandomString(constants.ClientSecretLength, constants.ClientSecretLength)
}

func GenerateRegistrationAccessToken() string {
	return GenerateRandomString(constants.RegistrationAccessTokenLength, constants.RegistrationAccessTokenLength)
}

func GetUrlWithQueryParams(redirectUri string, params map[string]string) string {
	parsedUrl, _ := url.Parse(redirectUri)
	query := parsedUrl.Query()
	for param, value := range params {
		query.Add(param, value)
	}
	parsedUrl.RawQuery = query.Encode()
	return parsedUrl.String()
}

func GetUrlWithFragmentParams(redirectUri string, params map[string]string) string {
	parsedUrl, _ := url.Parse(redirectUri)
	fragments, _ := url.ParseQuery(parsedUrl.Fragment)
	for param, value := range params {
		fragments.Add(param, value)
	}
	parsedUrl.Fragment = fragments.Encode()
	return parsedUrl.String()
}

func CreateSha256Hash(plainValue string) string {
	h := sha256.New()
	h.Write([]byte(plainValue))
	hashedCodeVerifier := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(hashedCodeVerifier))
}

func IsPkceValid(codeVerifier string, codeChallenge string, codeChallengeMethod constants.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case constants.PlainCodeChallengeMethod:
		return codeChallenge == codeVerifier
	case constants.Sha256CodeChallengeMethod:
		return codeChallenge == CreateSha256Hash(codeVerifier)
	}

	return false
}

// If either an empty or the "jwt" response modes are passed, we must find the default value based on the response type.
func GetResponseModeOrDefault(responseMode constants.ResponseMode, responseType constants.ResponseType) constants.ResponseMode {
	if responseMode == "" {
		return getDefaultResponseMode(responseType)
	}

	if responseMode == constants.JwtResponseMode {
		responseMode = getDefaultJarmResponseMode(responseType)
	}

	return responseMode
}

func getDefaultResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
	if responseType.IsImplicit() {
		return constants.FragmentResponseMode
	}

	return constants.QueryResponseMode
}

func getDefaultJarmResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
	if responseType.IsImplicit() {
		return constants.FragmentJwtResponseMode
	}

	return constants.QueryJwtResponseMode
}

func ContainsAll[T comparable](superSet []T, subSet ...T) bool {
	for _, e := range subSet {
		if !slices.Contains(superSet, e) {
			return false
		}
	}

	return true
}

// Return the first element in a slice for which the condition is true.
// If no element is found, 'ok' is set to false.
func FindFirst[T interface{}](slice []T, condition func(T) bool) (element T, ok bool) {
	for _, element = range slice {
		if condition(element) {
			return element, true
		}
	}

	return element, false
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

// Return true if any element in the slice respects the condition.
func Any[T interface{}](slice []T, condition func(T) bool) bool {
	for _, element := range slice {
		if condition(element) {
			return true
		}
	}

	return false
}

func AnyEmpty(values ...string) bool {
	return Any(
		values,
		func(s string) bool { return s == "" },
	)
}

func AnyNonEmpty(values ...string) bool {
	return Any(
		values,
		func(s string) bool { return s != "" },
	)
}

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

func GetTimestampNow() int {
	return int(time.Now().Unix())
}

func SplitStringWithSpaces(s string) []string {
	slice := []string{}
	if strings.ReplaceAll(strings.Trim(s, " "), " ", "") != "" {
		slice = strings.Split(s, " ")
	}

	return slice
}

func IsBlank(s string) bool {
	return strings.ReplaceAll(s, " ", "") == ""
}

func ScopesContainsOpenId(scope string) bool {
	return scope != "" && slices.Contains(SplitStringWithSpaces(scope), constants.OpenIdScope)
}

func GetNonEmptyOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).String() == "" {
		return s2
	}

	return s1
}

// Generate a JWK thumbprint for a valid DPoP JWT.
func GenerateJwkThumbprint(dpopJwt string, dpopSigningAlgorithms []jose.SignatureAlgorithm) string {
	parsedDpopJwt, _ := jwt.ParseSigned(dpopJwt, dpopSigningAlgorithms)
	jkt, _ := parsedDpopJwt.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(jkt)
}

func GenerateSha256Hash(s []byte) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func GenerateSha1Hash(s []byte) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func GenerateHalfHashClaim(claimValue string, idTokenAlgorithm jose.SignatureAlgorithm) string {
	var hash hash.Hash
	switch jose.SignatureAlgorithm(idTokenAlgorithm) {
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

func GetJwks(jwksUri string) (jose.JSONWebKeySet, error) {
	resp, err := http.Get(jwksUri)
	if err != nil || resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, errors.New("could not fetch client jwks")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return jose.JSONWebKeySet{}, errors.New("could not fetch client jwks")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(respBody, &jwks); err != nil {
		return jose.JSONWebKeySet{}, errors.New("could not parse client jwks")
	}

	return jwks, nil
}

func ContainsAllScopes(scopesSuperSet string, scopesSubSet string) bool {
	return ContainsAll(SplitStringWithSpaces(scopesSuperSet), SplitStringWithSpaces(scopesSubSet)...)
}

func IsJwt(token string) bool {
	isJwt, _ := regexp.MatchString("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)", token)
	return isJwt
}

func Remove[T comparable](slice []T, value T) []T {
	newSlice := []T{}
	for _, v := range slice {
		if v != value {
			newSlice = append(newSlice, v)
		}
	}

	return newSlice
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
