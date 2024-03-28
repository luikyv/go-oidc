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

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("request should be valid? %v. request data: %v", testCase.isValid, testCase.tokenRequest),
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
