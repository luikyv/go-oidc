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

func Random(length int) string {
	result := strings.Builder{}
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			panic(err)
		}
		result.WriteByte(charset[n.Int64()])
	}

	return result.String()
}
