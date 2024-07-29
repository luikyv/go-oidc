package goidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestAreScopesAllowed(t *testing.T) {
	// Given.
	scopes := []goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
		goidc.NewScope("scope3"),
	}
	ctx := goidc.NewTestContext(scopes)

	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			Scopes: "scope1 scope2 scope3",
		},
	}

	testCases := []struct {
		requestedScopes string
		expectedResult  bool
	}{
		{"scope1 scope3", true},
		{"scope3 scope2", true},
		{"invalid_scope scope3", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.expectedResult, client.AreScopesAllowed(ctx, scopes, testCase.requestedScopes))
			},
		)
	}
}

func TestIsResponseTypeAllowed(t *testing.T) {
	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		},
	}
	testCases := []struct {
		requestedResponseType goidc.ResponseType
		expectedResult        bool
	}{
		{goidc.ResponseTypeCode, true},
		{goidc.ResponseTypeCodeAndIDToken, false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.expectedResult, client.IsResponseTypeAllowed(testCase.requestedResponseType))
			},
		)
	}
}

func TestIsGrantTypeAllowed(t *testing.T) {
	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			GrantTypes: []goidc.GrantType{goidc.GrantClientCredentials},
		},
	}
	testCases := []struct {
		requestedGrantType goidc.GrantType
		expectedResult     bool
	}{
		{goidc.GrantClientCredentials, true},
		{goidc.GrantAuthorizationCode, false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.expectedResult, client.IsGrantTypeAllowed(testCase.requestedGrantType))
			},
		)
	}
}

func TestIsRedirectURIAllowed(t *testing.T) {
	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			RedirectURIS: []string{"https://example.com/callback", "http://example.com?param=value"},
		},
	}
	testCases := []struct {
		redirectURI    string
		expectedResult bool
	}{
		{"https://example.com/callback", true},
		{"https://example.com/callback?param=value", true},
		{"https://example.com/invalid", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.expectedResult, client.IsRedirectURIAllowed(testCase.redirectURI))
			},
		)
	}
}

func TestIsAuthorizationDetailTypeAllowed(t *testing.T) {
	// Given.
	client := goidc.Client{}

	// Then.
	assert.True(t, client.IsAuthorizationDetailTypeAllowed("random_type"),
		"when the client doesn't specify the detail types, any type should be accepted")

	// Given.
	client.AuthorizationDetailTypes = []string{"valid_type"}

	// Then.
	assert.True(t, client.IsAuthorizationDetailTypeAllowed("valid_type"),
		"the client specified the detail types, so an allowed type should be valid")

	// Then.
	assert.False(t, client.IsAuthorizationDetailTypeAllowed("random_type"),
		"the client specified the detail types, so a not allowed type shouldn't be valid")
}

func TestIsRegistrationAccessTokenValid(t *testing.T) {

	// Given.
	registrationAccessToken := "random_token"
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(registrationAccessToken), bcrypt.DefaultCost)
	client := goidc.Client{
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
	}

	// Then.
	assert.True(t, client.IsRegistrationAccessTokenValid(registrationAccessToken))
	assert.False(t, client.IsRegistrationAccessTokenValid("invalid_token"))
}

func TestGetPublicJWKS(t *testing.T) {

	// Given.
	numberOfRequestsToJWKSURI := 0
	// Mock the http request to return a JWKS with a random key.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numberOfRequestsToJWKSURI++
		jwk := PrivatePs256JWK("random_key_id")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}); err != nil {
			panic(err)
		}
	}))

	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKSURI: server.URL,
			PublicJWKS:    nil,
		},
	}

	for i := 0; i < 2; i++ {
		// When.
		jwks, err := client.FetchPublicJWKS()
		// Then.
		assert.Nil(t, err)
		assert.Equal(t, 1, numberOfRequestsToJWKSURI, "the jwks uri should've been requested once")
		assert.Len(t, jwks.Keys, 1, "the jwks was not fetched")
	}

}

func PrivatePs256JWK(keyID string) jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeyUsageSignature),
	}
}
