package unit

import (
	"math/rand"
	"net/url"
	"slices"

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

func GenerateAuthorizationCode() string {
	return GenerateRandomString(constants.AuthorizationCodeLength, constants.AuthorizationCodeLength)
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

func Contains[T comparable](superSet []T, subSet []T) bool {
	for _, e := range subSet {
		if !slices.Contains(superSet, e) {
			return false
		}
	}

	return true
}

func FindFirst[T interface{}](slice []T, filter func(T) bool) (element T, ok bool) {
	for _, element = range slice {
		if filter(element) {
			return element, true
		}
	}

	return element, false
}
