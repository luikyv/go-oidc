package authorize_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestValidateAuthorizationRequest(t *testing.T) {
	client := models.GetTestClient()

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
					ResponseType: goidc.CodeResponse,
					ResponseMode: goidc.QueryResponseMode,
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
					ResponseType: goidc.CodeResponse,
					Scopes:       goidc.OpenIdScope,
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
					ResponseType: goidc.CodeResponse,
					Scopes:       goidc.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				client.ResponseTypes = []goidc.ResponseType{}
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
					Scopes:      goidc.OpenIdScope,
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
					ResponseType: goidc.CodeResponse,
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
					ResponseType: goidc.CodeResponse,
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
	client := models.GetTestClient()

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
					ResponseType: goidc.CodeResponse,
					ResponseMode: goidc.QueryResponseMode,
					Scopes:       client.Scopes,
				},
			},
			models.AuthnSession{
				ClientId:           client.Id,
				ExpiresAtTimestamp: unit.GetTimestampNow() + 1,
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
					ResponseType: goidc.CodeAndIdTokenResponse,
					ResponseMode: goidc.FragmentResponseMode,
					Scopes:       goidc.OpenIdScope,
					Nonce:        "random_nonce",
				},
			},
			models.AuthnSession{
				ClientId:           client.Id,
				ExpiresAtTimestamp: unit.GetTimestampNow() + 1,
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
	client := models.GetTestClient()

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
					ResponseType: goidc.CodeResponse,
					ResponseMode: goidc.QueryResponseMode,
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
					ResponseType: goidc.CodeAndIdTokenResponse,
					ResponseMode: goidc.FragmentResponseMode,
					Scopes:       goidc.OpenIdScope,
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
