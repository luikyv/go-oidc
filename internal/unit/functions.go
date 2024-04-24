package unit

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
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

func SetHost(host string) {
	constants.Host = host
}

func GetHost() string {
	return constants.Host
}

func SetPrivateJWKS(privateJWKS jose.JSONWebKeySet) {
	constants.PrivateJWKS = privateJWKS
}

func GetPrivateKey(keyId string) (jose.JSONWebKey, bool) {
	keys := constants.PrivateJWKS.Key(keyId)
	if len(keys) != 1 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func GetPublicKey(keyId string) (jose.JSONWebKey, bool) {
	privateKey, ok := GetPrivateKey(keyId)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	publicKey := privateKey.Public()
	if publicKey.KeyID == "" {
		return jose.JSONWebKey{}, false
	}

	return publicKey, true
}

func GetPublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range constants.PrivateJWKS.Keys {
		publicKey := privateKey.Public()
		// If the key is not of assymetric type, publicKey holds a null value.
		// To know if it is the case, we'll check if its key ID is not a null value which would mean privateKey is symetric and cannot be public.
		if publicKey.KeyID != "" {
			publicKeys = append(publicKeys, privateKey.Public())
		}
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func GetSigningAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range constants.PrivateJWKS.Keys {
		if privateKey.Use == "sig" {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func IsPkceValid(codeVerifier string, codeChallenge string, codeChallengeMethod constants.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case constants.Plain:
		return codeChallenge == codeVerifier
	case constants.SHA256:
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		hashedCodeVerifier := h.Sum(nil)
		encodedHashedCodeVerifier := base64.URLEncoding.EncodeToString([]byte(hashedCodeVerifier))
		return codeChallenge == strings.Replace(string(encodedHashedCodeVerifier), "=", "", -1)
	}

	return false
}

func ResponseContainsCode(responseType constants.ResponseType) bool {
	return strings.Contains(string(responseType), string(constants.Code))
}

func ResponseContainsIdToken(responseType constants.ResponseType) bool {
	return strings.Contains(string(responseType), string(constants.IdToken))
}

func GetBearerToken(requestCtx *gin.Context) (string, bool) {
	bearerToken := requestCtx.Request.Header.Get("Authorization")
	if bearerToken == "" {
		return "", false
	}

	bearerTokenParts := strings.Split(bearerToken, " ")
	if len(bearerTokenParts) != 2 {
		return "", false
	}

	return bearerTokenParts[1], true
}

func Contains[T comparable](superSet []T, subSet []T) bool {
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

func GetTimestampNow() int {
	return int(time.Now().Unix())
}

func SplitStringWithSpaces(s string) []string {
	slice := []string{}
	if s != "" {
		slice = strings.Split(s, " ")
	}

	return slice
}

func SplitResponseTypes(s string) []constants.ResponseType {
	responseTypes := []constants.ResponseType{}
	if s == "" {
		return responseTypes
	}

	for _, responseType := range strings.Split(s, " ") {
		responseTypes = append(responseTypes, constants.ResponseType(responseType))
	}

	return responseTypes
}
