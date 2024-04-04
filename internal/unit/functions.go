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
	return fmt.Sprintf("urn:%s:request_uri:%s", constants.RequestUriDomain, GenerateRandomString(constants.RequestUriLength, constants.RequestUriLength))
}

func GenerateAuthorizationCode() string {
	return GenerateRandomString(constants.AuthorizationCodeLength, constants.AuthorizationCodeLength)
}

func GenerateRefreshToken() string {
	return GenerateRandomString(constants.RefreshTokenLength, constants.RefreshTokenLength)
}

func GetUrlWithParams(redirectUri string, params map[string]string) string {
	u, _ := url.Parse(redirectUri)
	q := u.Query()
	for p, v := range params {
		q.Add(p, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func SetPrivateJWKS(privateJWKS jose.JSONWebKeySet) {
	constants.PrivateJWKS = privateJWKS
}

func SetPublicJWKS(publicJWKS jose.JSONWebKeySet) {
	constants.PublicJWKS = publicJWKS
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
