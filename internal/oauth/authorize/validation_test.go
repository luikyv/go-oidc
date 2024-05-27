package authorize_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/authorize"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestValidateAuthorizationRequest(t *testing.T) {
	client := models.GetTestClientWithNoneAuthn()

	var cases = []struct {
		Name                string
		Req                 models.AuthorizationRequest
		ClientModifyFunc    func(client models.Client) models.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					ResponseMode: constants.QueryResponseMode,
					Scopes:       client.Scopes,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scopes:       constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
		{
			"oauth_request_invalid_response_type",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scopes:       constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				client.ResponseTypes = []constants.ResponseType{}
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_missing_response_type",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri: client.RedirectUris[0],
					Scopes:      constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_invalid_scope",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scopes:       "invalid_scope",
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_invalid_redirect_uri",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  "https://invalid.com",
					ResponseType: constants.CodeResponse,
					Scopes:       client.Scopes,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
			false,
		},
	}

	for _, c := range cases {
		t.Run(
			c.Name,
			func(t *testing.T) {
				// Then.
				err := authorize.ValidateAuthorizationRequest(
					utils.GetDummyTestContext(),
					c.Req,
					c.ClientModifyFunc(client),
				)

				// Assert.
				isValid := err == nil
				if isValid != c.ShouldBeValid {
					t.Errorf("expected: %v - actual: %v - error: %s", c.ShouldBeValid, isValid, err)
					return
				}

				_, ok := err.(models.OAuthRedirectError)
				if c.ShouldRedirectError && !ok {
					t.Errorf("error is not of type redirect. Error: %v", err)
				}
			},
		)
	}

}

func TestValidateAuthorizationRequestWithPar(t *testing.T) {
	client := models.GetTestClientWithNoneAuthn()

	var cases = []struct {
		Name                string
		Req                 models.AuthorizationRequest
		Session             models.AuthnSession
		ClientModifyFunc    func(client models.Client) models.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			models.AuthorizationRequest{
				ClientId: client.Id,
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					ResponseMode: constants.QueryResponseMode,
					Scopes:       client.Scopes,
				},
			},
			models.AuthnSession{
				ClientId:           client.Id,
				CreatedAtTimestamp: unit.GetTimestampNow(),
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			models.AuthorizationRequest{
				ClientId: client.Id,
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeAndIdTokenResponse,
					ResponseMode: constants.FragmentResponseMode,
					Scopes:       constants.OpenIdScope,
					Nonce:        "random_nonce",
				},
			},
			models.AuthnSession{
				ClientId:           client.Id,
				CreatedAtTimestamp: unit.GetTimestampNow(),
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri: client.RedirectUris[0],
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
	}

	for _, c := range cases {
		t.Run(
			c.Name,
			func(t *testing.T) {
				// Then.
				err := authorize.ValidateAuthorizationRequestWithPar(
					utils.GetDummyTestContext(),
					c.Req,
					c.Session,
					c.ClientModifyFunc(client),
				)

				// Assert.
				isValid := err == nil
				if isValid != c.ShouldBeValid {
					t.Errorf("expected: %v - actual: %v - error: %s", c.ShouldBeValid, isValid, err)
					return
				}

				_, ok := err.(models.OAuthRedirectError)
				if c.ShouldRedirectError && !ok {
					t.Errorf("error is not of type redirect. Error: %v", err)
				}
			},
		)
	}
}

func TestValidateAuthorizationRequestWithJar(t *testing.T) {
	client := models.GetTestClientWithNoneAuthn()

	var cases = []struct {
		Name                string
		Req                 models.AuthorizationRequest
		Jar                 models.AuthorizationRequest
		ClientModifyFunc    func(client models.Client) models.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			models.AuthorizationRequest{
				ClientId: client.Id,
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					ResponseMode: constants.QueryResponseMode,
					Scopes:       client.Scopes,
					Nonce:        "random_nonce",
				},
			},
			models.AuthorizationRequest{
				ClientId:                client.Id,
				AuthorizationParameters: models.AuthorizationParameters{},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			models.AuthorizationRequest{
				ClientId: client.Id,
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  client.RedirectUris[0],
					ResponseType: constants.CodeAndIdTokenResponse,
					ResponseMode: constants.FragmentResponseMode,
					Scopes:       constants.OpenIdScope,
				},
			},
			models.AuthorizationRequest{
				ClientId: client.Id,
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri: client.RedirectUris[0],
					Nonce:       "random_nonce",
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
			false,
		},
		{
			"client_id_does_not_match",
			models.AuthorizationRequest{
				ClientId: client.Id,
			},
			models.AuthorizationRequest{
				ClientId: "invalid_client_id",
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
			false,
		},
	}

	for _, c := range cases {
		t.Run(
			c.Name,
			func(t *testing.T) {
				// Then.
				err := authorize.ValidateAuthorizationRequestWithJar(
					utils.GetDummyTestContext(),
					c.Req,
					c.Jar,
					c.ClientModifyFunc(client),
				)

				// Assert.
				isValid := err == nil
				if isValid != c.ShouldBeValid {
					t.Errorf("expected: %v - actual: %v - error: %s", c.ShouldBeValid, isValid, err)
					return
				}

				_, ok := err.(models.OAuthRedirectError)
				if c.ShouldRedirectError && !ok {
					t.Errorf("error is not of type redirect. Error: %v", err)
				}
			},
		)
	}
}
