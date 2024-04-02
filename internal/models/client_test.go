package models

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

func TestNoneAuthenticatorValidInfo(t *testing.T) {
	authenticator := NoneClientAuthenticator{}
	req := ClientAuthnRequest{
		ClientId: "client_id",
	}

	if !authenticator.IsAuthenticated(req) {
		t.Error("The client should be authenticated")
	}
}

func TestNoneAuthenticatorInvalidInfo(t *testing.T) {
	authenticator := NoneClientAuthenticator{}
	req := ClientAuthnRequest{
		ClientId:     "client_id",
		ClientSecret: "client_secret",
	}
	if authenticator.IsAuthenticated(req) {
		t.Error("The client should not be authenticated")
	}
}

func TestSecretClientAuthenticatorValidInfo(t *testing.T) {
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	authenticator := SecretClientAuthenticator{
		HashedSecret: string(hashedClientSecret),
	}
	req := ClientAuthnRequest{
		ClientId:     "client_id",
		ClientSecret: clientSecret,
	}

	if !authenticator.IsAuthenticated(req) {
		t.Error("The client should be authenticated")
	}
}

func TestSecretClientAuthenticatorInvalidInfo(t *testing.T) {
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	authenticator := SecretClientAuthenticator{
		HashedSecret: string(hashedClientSecret),
	}
	req := ClientAuthnRequest{
		ClientId:     "client_id",
		ClientSecret: "invalid_secret",
	}

	if authenticator.IsAuthenticated(req) {
		t.Error("The client should not be authenticated")
	}
}

func TestPrivateKeyJWTClientAuthenticatorValidInfo(t *testing.T) {
	jwk := JWK{
		KeyType:          constants.Octet,
		KeyId:            "0afee142-a0af-4410-abcc-9f2d44ff45b5",
		SigningAlgorithm: constants.HS256,
		Key:              "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
	}
	authenticator := PrivateKeyJwtClientAuthenticator{
		PublicJwk: jwk,
	}
	clientId := "random_client_id"
	createdAtTimestamp := unit.GetTimestampNow()
	tokenString, _ := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": clientId,
			"iss": clientId,
			"exp": createdAtTimestamp + 60,
			"iat": createdAtTimestamp,
		},
	).SignedString([]byte(jwk.Key))
	req := ClientAuthnRequest{
		ClientId:            clientId,
		ClientAssertionType: constants.JWTBearer,
		ClientAssertion:     tokenString,
	}

	if !authenticator.IsAuthenticated(req) {
		t.Error("The client should be authenticated")
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
