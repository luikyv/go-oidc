package authorize_test

import (
	"testing"
	"time"

	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthorizationRequest(t *testing.T) {
	client := oidctest.NewClient(t)

	var cases = []struct {
		Name                string
		Req                 authorize.Request
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			authorize.Request{
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
			authorize.Request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       goidc.ScopeOpenID.ID,
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
			authorize.Request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       goidc.ScopeOpenID.ID,
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
			authorize.Request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIS[0],
					Scopes:      goidc.ScopeOpenID.ID,
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
			authorize.Request{
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
			authorize.Request{
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
				err := authorize.ValidateRequest(
					oidctest.NewContext(t),
					c.Req,
					c.ClientModifyFunc(client),
				)

				// Then.
				require.Equal(t, c.ShouldBeValid, err == nil)
				if err == nil {
					return
				}

				if c.ShouldRedirectError {
					var redirectErr authorize.RedirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr oidc.Error
					assert.ErrorAs(t, err, &oauthErr)
				}

			},
		)
	}

}

func TestValidateAuthorizationRequestWithPAR(t *testing.T) {
	client := oidctest.NewClient(t)

	var cases = []struct {
		Name                string
		Req                 authorize.Request
		Session             *goidc.AuthnSession
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			authorize.Request{
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
				ExpiresAtTimestamp: time.Now().Unix() + 10,
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			authorize.Request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.ID,
					Nonce:        "random_nonce",
				},
			},
			&goidc.AuthnSession{
				ClientID:           client.ID,
				ExpiresAtTimestamp: time.Now().Unix() + 10,
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
				ctx := oidctest.NewContext(t)
				err := authorize.ValidateRequestWithPAR(
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
					var redirectErr authorize.RedirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr oidc.Error
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}

func TestValidateAuthorizationRequestWithJAR(t *testing.T) {
	client := oidctest.NewClient(t)

	var cases = []struct {
		Name                string
		Req                 authorize.Request
		JAR                 authorize.Request
		ClientModifyFunc    func(client *goidc.Client) *goidc.Client
		ShouldBeValid       bool
		ShouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			authorize.Request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.Scopes,
					Nonce:        "random_nonce",
				},
			},
			authorize.Request{
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
			authorize.Request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIS[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.ID,
				},
			},
			authorize.Request{
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
			authorize.Request{
				ClientID: client.ID,
			},
			authorize.Request{
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
				err := authorize.ValidateRequestWithJAR(
					oidctest.NewContext(t),
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
					var redirectErr authorize.RedirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr oidc.Error
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}
