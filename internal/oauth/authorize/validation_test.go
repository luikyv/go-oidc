package authorize_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/oauth/authorize"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthorizationRequest(t *testing.T) {
	client := utils.NewTestClient(t)

	var cases = []struct {
		Name                string
		Req                 utils.AuthorizationRequest
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.Scopes,
				},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       goidc.ScopeOpenID.String(),
				},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"oauth_request_invalid_response_type",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       goidc.ScopeOpenID.String(),
				},
			},
			func(client *goidc.Client) *goidc.Client {
				client.ResponseTypes = []goidc.ResponseType{}
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_missing_response_type",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIS[0],
					Scopes:      goidc.ScopeOpenID.String(),
				},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_invalid_scope",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       "invalid_scope",
				},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			false,
			true,
		},
		{
			"oauth_request_invalid_redirect_uri",
			utils.AuthorizationRequest{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  "https://invalid.com",
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       client.Scopes,
				},
			},
			func(client *goidc.Client) *goidc.Client {
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
				// When.
				err := authorize.ValidateAuthorizationRequest(
					utils.NewTestContext(t),
					c.Req,
					c.ClientModifyFunc(client),
				)

				// Then.
				require.Equal(t, c.ShouldBeValid, err == nil)
				if err == nil {
					return
				}

				if c.ShouldRedirectError {
					var redirectErr goidc.OAuthRedirectError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr goidc.OAuthBaseError
					assert.ErrorAs(t, err, &oauthErr)
				}

			},
		)
	}

}

func TestValidateAuthorizationRequestWithPAR(t *testing.T) {
	client := utils.NewTestClient(t)

	var cases = []struct {
		Name                string
		Req                 utils.AuthorizationRequest
		Session             *goidc.AuthnSession
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			utils.AuthorizationRequest{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.Scopes,
				},
			},
			&goidc.AuthnSession{
				ClientID:           client.ID,
				ExpiresAtTimestamp: goidc.TimestampNow() + 10,
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			utils.AuthorizationRequest{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.String(),
					Nonce:        "random_nonce",
				},
			},
			&goidc.AuthnSession{
				ClientID:           client.ID,
				ExpiresAtTimestamp: goidc.TimestampNow() + 10,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIS[0],
				},
			},
			func(client *goidc.Client) *goidc.Client {
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
				// When.
				ctx := utils.NewTestContext(t)
				err := authorize.ValidateAuthorizationRequestWithPAR(
					ctx,
					c.Req,
					c.Session,
					c.ClientModifyFunc(client),
				)

				// Then.
				require.Equal(t, c.ShouldBeValid, err == nil, err)
				if err == nil {
					return
				}

				if c.ShouldRedirectError {
					var redirectErr goidc.OAuthRedirectError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr goidc.OAuthBaseError
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}

func TestValidateAuthorizationRequestWithJAR(t *testing.T) {
	client := utils.NewTestClient(t)

	var cases = []struct {
		Name                string
		Req                 utils.AuthorizationRequest
		JAR                 utils.AuthorizationRequest
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			utils.AuthorizationRequest{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.Scopes,
					Nonce:        "random_nonce",
				},
			},
			utils.AuthorizationRequest{
				ClientID:                client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			utils.AuthorizationRequest{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.String(),
				},
			},
			utils.AuthorizationRequest{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIS[0],
					Nonce:       "random_nonce",
				},
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"client_id_does_not_match",
			utils.AuthorizationRequest{
				ClientID: client.ID,
			},
			utils.AuthorizationRequest{
				ClientID: "invalid_client_id",
			},
			func(client *goidc.Client) *goidc.Client {
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
				// When.
				err := authorize.ValidateAuthorizationRequestWithJAR(
					utils.NewTestContext(t),
					c.Req,
					c.JAR,
					c.ClientModifyFunc(client),
				)

				// Then.
				require.Equal(t, c.ShouldBeValid, err == nil)
				if err == nil {
					return
				}

				if c.ShouldRedirectError {
					var redirectErr goidc.OAuthRedirectError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr goidc.OAuthBaseError
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}
