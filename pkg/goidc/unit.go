package goidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"slices"
	"strings"
	"time"
)

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

func GenerateCallbackId() string {
	return GenerateRandomString(CallbackIdLength, CallbackIdLength)
}

func GenerateAuthorizationCode() string {
	return GenerateRandomString(AuthorizationCodeLength, AuthorizationCodeLength)
}

func GenerateRequestUri() string {
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", GenerateRandomString(RequestUriLength, RequestUriLength))
}

func GenerateRandomString(minLength int, maxLength int) string {

	length := minLength + rand.Intn(maxLength-minLength+1) // minLength >= length <= maxLength
	randomStringInBytes := make([]byte, length)
	charSetSize := len(Charset)
	for i := range randomStringInBytes {
		// Set a random character to randomStringInBytes[i]
		randomStringInBytes[i] = Charset[rand.Intn(charSetSize)]
	}

	return string(randomStringInBytes)
}

func GetJwks(jwksUri string) (JsonWebKeySet, error) {
	resp, err := http.Get(jwksUri)
	if err != nil || resp.StatusCode != http.StatusOK {
		return JsonWebKeySet{}, errors.New("could not fetch client jwks")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return JsonWebKeySet{}, errors.New("could not fetch client jwks")
	}

	var jwks JsonWebKeySet
	if err := json.Unmarshal(respBody, &jwks); err != nil {
		return JsonWebKeySet{}, errors.New("could not parse client jwks")
	}

	return jwks, nil
}

func ContainsAllScopes(scopesSuperSet string, scopesSubSet string) bool {
	return ContainsAll(SplitStringWithSpaces(scopesSuperSet), SplitStringWithSpaces(scopesSubSet)...)
}

func ContainsAll[T comparable](superSet []T, subSet ...T) bool {
	for _, e := range subSet {
		if !slices.Contains(superSet, e) {
			return false
		}
	}

	return true
}
