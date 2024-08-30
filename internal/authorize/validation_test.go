package authorize

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestValidateRequest(t *testing.T) {
	client, _ := oidctest.NewClient(t)

	var cases = []struct {
		name                string
		req                 request
		modifiedClient      func(client *goidc.Client) *goidc.Client
		shouldBeValid       bool
		shouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.ScopeIDs,
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
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
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
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
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
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIs[0],
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
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
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
			request{
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  "https://invalid.com",
					ResponseType: goidc.ResponseTypeCode,
					Scopes:       client.ScopeIDs,
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
			c.name,
			func(t *testing.T) {
				// When.
				err := validateRequest(
					oidctest.NewContext(t),
					c.req,
					c.modifiedClient(client),
				)

				// Then.
				isValid := err == nil
				if isValid != c.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, c.shouldBeValid)
				}
				if err == nil {
					return
				}

				if c.shouldRedirectError {
					var redirectErr redirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr error
					assert.ErrorAs(t, err, &oauthErr)
				}

			},
		)
	}

}

func TestValidateRequestWithPAR(t *testing.T) {
	client, _ := oidctest.NewClient(t)

	var cases = []struct {
		name                string
		req                 request
		session             *goidc.AuthnSession
		modifiedClient      func(client *goidc.Client) *goidc.Client
		shouldBeValid       bool
		shouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.ScopeIDs,
				},
			},
			&goidc.AuthnSession{
				ClientID:           client.ID,
				ExpiresAtTimestamp: timeutil.TimestampNow() + 10,
			},
			func(client *goidc.Client) *goidc.Client {
				return client
			},
			true,
			false,
		},
		{
			"valid_openid_request",
			request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.ID,
					Nonce:        "random_nonce",
				},
			},
			&goidc.AuthnSession{
				ClientID:           client.ID,
				ExpiresAtTimestamp: timeutil.TimestampNow() + 10,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIs[0],
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
			c.name,
			func(t *testing.T) {
				// When.
				ctx := oidctest.NewContext(t)
				err := validateRequestWithPAR(
					ctx,
					c.req,
					c.session,
					c.modifiedClient(client),
				)

				// Then.
				isValid := err == nil
				if isValid != c.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, c.shouldBeValid)
				}
				if err == nil {
					return
				}

				if c.shouldRedirectError {
					var redirectErr redirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr error
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}

func TestValidateRequestWithJAR(t *testing.T) {
	client, _ := oidctest.NewClient(t)

	var cases = []struct {
		name                string
		req                 request
		jar                 request
		modifiedClientFunc  func(client *goidc.Client) *goidc.Client
		shouldBeValid       bool
		shouldRedirectError bool
	}{
		{
			"valid_oauth_request",
			request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					ResponseType: goidc.ResponseTypeCode,
					ResponseMode: goidc.ResponseModeQuery,
					Scopes:       client.ScopeIDs,
					Nonce:        "random_nonce",
				},
			},
			request{
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
			request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					ResponseType: goidc.ResponseTypeCodeAndIDToken,
					ResponseMode: goidc.ResponseModeFragment,
					Scopes:       goidc.ScopeOpenID.ID,
				},
			},
			request{
				ClientID: client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					RedirectURI: client.RedirectURIs[0],
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
			request{
				ClientID: client.ID,
			},
			request{
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
			c.name,
			func(t *testing.T) {
				// When.
				err := validateRequestWithJAR(
					oidctest.NewContext(t),
					c.req,
					c.jar,
					c.modifiedClientFunc(client),
				)

				// Then.
				isValid := err == nil
				if isValid != c.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, c.shouldBeValid)
				}
				if err == nil {
					return
				}

				if c.shouldRedirectError {
					var redirectErr redirectionError
					assert.ErrorAs(t, err, &redirectErr)
				} else {
					var oauthErr error
					assert.ErrorAs(t, err, &oauthErr)
				}
			},
		)
	}
}
