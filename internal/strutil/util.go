// Package strutil contains functions to help handling strings.
package strutil

import (
	"crypto/rand"
	"math/big"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func ContainsOpenID(scopes string) bool {
	return slices.Contains(SplitWithSpaces(scopes), goidc.ScopeOpenID.ID)
}

func ContainsOfflineAccess(scopes string) bool {
	return slices.Contains(SplitWithSpaces(scopes), goidc.ScopeOfflineAccess.ID)
}

func SplitWithSpaces(s string) []string {
	slice := []string{}
	if strings.ReplaceAll(strings.Trim(s, " "), " ", "") != "" {
		slice = strings.Split(s, " ")
	}

	return slice
}

func Random(length int) (string, error) {
	charsetLen := int64(len(charset))
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(charsetLen))
		if err != nil {
			return "", err
		}
		ret[i] = charset[num.Int64()]
	}

	return string(ret), nil
}
