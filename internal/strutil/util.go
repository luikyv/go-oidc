// Package strutil contains functions to help handling strings.
package strutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
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

func NormalizeURL(inputURL string) (string, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}

	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)
	parsedURL.Host = strings.ToLower(parsedURL.Host)
	parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":")

	// Remove the port if it's the default for the scheme
	if (parsedURL.Scheme == "http" && parsedURL.Port() == "80") ||
		(parsedURL.Scheme == "https" && parsedURL.Port() == "443") {
		parsedURL.Host = parsedURL.Hostname()
	}

	// Remove the trailing slash if present in the path
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")

	// Remove query and fragment
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return parsedURL.String(), nil
}

func IsURL(str string) bool {
	parsedURL, err := url.ParseRequestURI(str)
	if err != nil {
		return false
	}

	return parsedURL.Scheme != "" && parsedURL.Host != ""
}
