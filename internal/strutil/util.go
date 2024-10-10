// Package strutil contains functions to help handling strings.
package strutil

import (
	"crypto/rand"
	"math/big"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
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
	charsetLen := int64(len(charset))
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(charsetLen))
		if err != nil {
			panic(err)
		}
		ret[i] = charset[num.Int64()]
	}

	return string(ret)
}

func BCryptHash(s string) string {
	hashedS, err := bcrypt.GenerateFromPassword(
		[]byte(s),
		bcrypt.DefaultCost,
	)
	if err != nil {
		panic(err)
	}
	return string(hashedS)
}
