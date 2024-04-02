package models_test

import (
	"fmt"
	"testing"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func getValidTokenRequestForClientCredentials() models.TokenRequest {
	return models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: "client_id",
		},
		GrantType: constants.ClientCredentials,
		Scope:     "scope1 scope2",
	}
}

func TestTokenRequestIsValidWhenGrantTypeIsClientCredentials(t *testing.T) {

	// When.
	testCases := []struct {
		isValid      bool
		tokenRequest models.TokenRequest
	}{
		{true, getValidTokenRequestForClientCredentials()},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForClientCredentials()
				req.AuthorizationCode = "random_authorization_code"
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForClientCredentials()
				req.RedirectUri = "random_redirect_uri"
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForClientCredentials()
				req.RefreshToken = "random_refresh_token"
				return req
			}(),
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {

				// Then.
				err := testCase.tokenRequest.IsValid()

				// Assert.
				actualIsValid := err == nil
				if actualIsValid != testCase.isValid {
					t.Error("invalid result")
				}

			},
		)
	}

}

func getValidTokenRequestForAuthorizationCodeGrant() models.TokenRequest {
	return models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: "client_id",
		},
		GrantType:         constants.AuthorizationCode,
		AuthorizationCode: "random_authorization_code",
		RedirectUri:       "random_redirect_uri",
	}
}

func TestTokenRequestIsValidWhenGrantTypeIsAuthorizationCode(t *testing.T) {

	// When.
	testCases := []struct {
		isValid      bool
		tokenRequest models.TokenRequest
	}{
		{true, getValidTokenRequestForAuthorizationCodeGrant()},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForAuthorizationCodeGrant()
				req.AuthorizationCode = ""
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForAuthorizationCodeGrant()
				req.RedirectUri = ""
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForAuthorizationCodeGrant()
				req.Scope = "scope1"
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForAuthorizationCodeGrant()
				req.RefreshToken = "random_refresh_token"
				return req
			}(),
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {

				// Then.
				err := testCase.tokenRequest.IsValid()

				// Assert.
				actualIsValid := err == nil
				if actualIsValid != testCase.isValid {
					t.Error("invalid result")
				}

			},
		)
	}

}

func getValidTokenRequestForRefreshTokenGrant() models.TokenRequest {
	return models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: "client_id",
		},
		GrantType:    constants.RefreshToken,
		RefreshToken: "random_refresh_token",
	}
}

func TestTokenRequestIsValidWhenGrantTypeIsRefreshToken(t *testing.T) {

	// When.
	testCases := []struct {
		isValid      bool
		tokenRequest models.TokenRequest
	}{
		{true, getValidTokenRequestForRefreshTokenGrant()},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForRefreshTokenGrant()
				req.RefreshToken = ""
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForRefreshTokenGrant()
				req.AuthorizationCode = "random_authorization_code"
				return req
			}(),
		},
		{
			false,
			func() models.TokenRequest {
				req := getValidTokenRequestForRefreshTokenGrant()
				req.RedirectUri = "random_redirect_uri"
				return req
			}(),
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {

				// Then.
				err := testCase.tokenRequest.IsValid()

				// Assert.
				actualIsValid := err == nil
				if actualIsValid != testCase.isValid {
					t.Error("invalid result")
				}

			},
		)
	}

}
