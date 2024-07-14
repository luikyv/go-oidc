package goidc

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Get the current timestamp. The result is always on UTC time.
func TimestampNow() int {
	return int(time.Now().Unix())
}

func SplitStringWithSpaces(s string) []string {
	slice := []string{}
	if strings.ReplaceAll(strings.Trim(s, " "), " ", "") != "" {
		slice = strings.Split(s, " ")
	}

	return slice
}

func CallbackID() (string, error) {
	return RandomString(CallbackIDLength)
}

func AuthorizationCode() (string, error) {
	return RandomString(AuthorizationCodeLength)
}

func RequestURI() (string, error) {
	s, err := RandomString(RequestURILength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", s), nil
}

func RandomString(n int) (string, error) {
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(ClientSecretCharset))))
		if err != nil {
			return "", err
		}
		ret[i] = ClientSecretCharset[num.Int64()]
	}

	return string(ret), nil
}

func FetchJWKS(jwksURI string) (JSONWebKeySet, error) {
	resp, err := http.Get(jwksURI)
	if err != nil || resp.StatusCode != http.StatusOK {
		return JSONWebKeySet{}, errors.New("could not fetch client jwks")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return JSONWebKeySet{}, errors.New("could not fetch client jwks")
	}

	var jwks JSONWebKeySet
	if err := json.Unmarshal(respBody, &jwks); err != nil {
		return JSONWebKeySet{}, errors.New("could not parse client jwks")
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
