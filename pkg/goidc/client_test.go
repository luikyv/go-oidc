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
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestAreScopesAllowed(t *testing.T) {
	// Given.
	ctx := goidc.GetTestContext(
		[]goidc.Scope{
			goidc.NewScope("scope1"),
			goidc.NewScope("scope2"),
			goidc.NewScope("scope3"),
		},
	)

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
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				if client.AreScopesAllowed(ctx, testCase.requestedScopes) != testCase.expectedResult {
					t.Error(testCase)
				}
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
				if client.IsResponseTypeAllowed(testCase.requestedResponseType) != testCase.expectedResult {
					t.Error(testCase)
				}
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
				if client.IsGrantTypeAllowed(testCase.requestedGrantType) != testCase.expectedResult {
					t.Error(testCase)
				}
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
				if client.IsRedirectURIAllowed(testCase.redirectURI) != testCase.expectedResult {
					t.Error(testCase)
				}
			},
		)
	}
}

func TestIsAuthorizationDetailTypeAllowed(t *testing.T) {
	// When.
	client := goidc.Client{}

	// Then.
	isValid := client.IsAuthorizationDetailTypeAllowed("random_type")

	// Assert.
	if !isValid {
		t.Error("when the client doesn't specify the detail types, any type should be accepted")
	}

	// When.
	client.AuthorizationDetailTypes = []string{"valid_type"}

	// Then.
	isValid = client.IsAuthorizationDetailTypeAllowed("valid_type")

	// Assert.
	if !isValid {
		t.Error("the client specified the detail types, so an allowed type should be valid")
	}

	// Then.
	isValid = client.IsAuthorizationDetailTypeAllowed("random_type")

	// Assert.
	if isValid {
		t.Error("the client specified the detail types, so a not allowed type shouldn't be valid")
	}
}

func TestIsRegistrationAccessTokenValid(t *testing.T) {
	registrationAccessToken := "random_token"
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(registrationAccessToken), bcrypt.DefaultCost)
	client := goidc.Client{
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
	}

	if client.IsRegistrationAccessTokenValid("invalid_token") {
		t.Errorf("the token should not be valid")
	}

	if !client.IsRegistrationAccessTokenValid(registrationAccessToken) {
		t.Errorf("the token should be valid")
	}
}

func TestGetPublicJWKS(t *testing.T) {

	// When.
	numberOfRequestsToJWKSURI := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numberOfRequestsToJWKSURI++
		jwk := GetTestPrivatePs256JWK("random_key_id")
		if err := json.NewEncoder(w).Encode(goidc.JSONWebKeySet{
			Keys: []goidc.JSONWebKey{jwk},
		}); err != nil {
			panic(err)
		}
	}))

	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKSURI: server.URL,
			PublicJWKS:    &goidc.JSONWebKeySet{},
		},
	}

	// Then.
	jwks, err := client.GetPublicJWKS()

	// Assert.
	if err != nil {
		t.Errorf("error fetching the JWKS")
		return
	}

	if numberOfRequestsToJWKSURI != 1 {
		t.Errorf("the jwks uri should've been requested once")
	}

	if len(jwks.Keys) == 0 {
		t.Errorf("the jwks was not fetched")
	}

	// Then.
	jwks, err = client.GetPublicJWKS()

	// Assert.
	if err != nil {
		t.Errorf("error fetching the JWKS the second time")
		return
	}

	if numberOfRequestsToJWKSURI != 1 {
		t.Errorf("the jwks uri should've been cached and therefore requested only once")
	}

	if len(jwks.Keys) == 0 {
		t.Errorf("the jwks was not fetched")
	}
}

func GetTestPrivatePs256JWK(keyID string) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeyUsageSignature),
	})
}
