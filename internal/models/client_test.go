package models

import (
	"fmt"
	"testing"

	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

func TestNoneAuthenticatorValidInfo(t *testing.T) {
	authenticator := NoneClientAuthenticator{}
	authnContext := ClientAuthnContext{
		ClientId: "client_id",
	}

	if !authenticator.IsAuthenticated(authnContext) {
		t.Error("The client should be authenticated")
	}
}

func TestNoneAuthenticatorInvalidInfo(t *testing.T) {
	authenticator := NoneClientAuthenticator{}
	authnContext := ClientAuthnContext{
		ClientId:     "client_id",
		ClientSecret: "client_secret",
	}
	if authenticator.IsAuthenticated(authnContext) {
		t.Error("The client should not be authenticated")
	}
}

func TestSecretClientAuthenticatorValidInfo(t *testing.T) {
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	authenticator := SecretClientAuthenticator{
		HashedSecret: string(hashedClientSecret),
	}
	authnContext := ClientAuthnContext{
		ClientId:     "client_id",
		ClientSecret: clientSecret,
	}

	if !authenticator.IsAuthenticated(authnContext) {
		t.Error("The client should be authenticated")
	}
}

func TestSecretClientAuthenticatorInvalidInfo(t *testing.T) {
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	authenticator := SecretClientAuthenticator{
		HashedSecret: string(hashedClientSecret),
	}
	authnContext := ClientAuthnContext{
		ClientId:     "client_id",
		ClientSecret: "invalid_secret",
	}

	if authenticator.IsAuthenticated(authnContext) {
		t.Error("The client should not be authenticated")
	}
}

func TestAreScopesAllowed(t *testing.T) {
	client := Client{
		Scopes: []string{"scope1", "scope2", "scope3"},
	}
	testCases := []struct {
		requestedScopes []string
		expectedResult  bool
	}{
		{[]string{"scope1", "scope3"}, true},
		{[]string{"invalid_scope", "scope3"}, false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("requested scopes: %v", testCase.requestedScopes),
			func(t *testing.T) {
				if client.AreScopesAllowed(testCase.requestedScopes) != testCase.expectedResult {
					t.Errorf("the scopes %v should be valid? %v", testCase.requestedScopes, testCase.expectedResult)
				}
			},
		)
	}
}

func TestAreResponseTypesAllowed(t *testing.T) {
	client := Client{
		ResponseTypes: []constants.ResponseType{constants.Code},
	}
	testCases := []struct {
		requestedResponseTypes []string
		expectedResult         bool
	}{
		{[]string{"code"}, true},
		{[]string{"code", "token"}, false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprint(testCase.requestedResponseTypes),
			func(t *testing.T) {
				if client.AreResponseTypesAllowed(testCase.requestedResponseTypes) != testCase.expectedResult {
					t.Errorf("the response types %v should be valid? %v", testCase.requestedResponseTypes, testCase.expectedResult)
				}
			},
		)
	}
}

func TestIsGrantTypeAllowed(t *testing.T) {
	client := Client{
		GrantTypes: []constants.GrantType{constants.ClientCredentials},
	}
	testCases := []struct {
		requestedGrantType constants.GrantType
		expectedResult     bool
	}{
		{constants.ClientCredentials, true},
		{constants.AuthorizationCode, false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprint(testCase.requestedGrantType),
			func(t *testing.T) {
				if client.IsGrantTypeAllowed(testCase.requestedGrantType) != testCase.expectedResult {
					t.Errorf("the grant type %v should be allowed? %v", testCase.requestedGrantType, testCase.expectedResult)
				}
			},
		)
	}
}

func TestIsRedirectUriAllowed(t *testing.T) {
	client := Client{
		RedirectUris: []string{"https://example.com/callback", "http://example.com?param=value"},
	}
	testCases := []struct {
		redirectUri    string
		expectedResult bool
	}{
		{"https://example.com/callback", true},
		{"https://example.com/invalid", false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprint(testCase.redirectUri),
			func(t *testing.T) {
				if client.IsRedirectUriAllowed(testCase.redirectUri) != testCase.expectedResult {
					t.Errorf("the redirect URI %v should be allowed? %v", testCase.redirectUri, testCase.expectedResult)
				}
			},
		)
	}
}
