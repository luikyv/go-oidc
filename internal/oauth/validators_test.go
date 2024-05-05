package oauth_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestValidateClientAuthnRequest(t *testing.T) {
	// When.
	expectedClientId := "random_client_id"
	var cases = []struct {
		Name          string
		Req           models.ClientAuthnRequest
		ShouldBeValid bool
	}{
		{
			"valid_secret_basic",
			models.ClientAuthnRequest{
				ClientIdBasicAuthn:     expectedClientId,
				ClientSecretBasicAuthn: "random_secret",
			},
			true,
		},
		{
			"valid_secret_post",
			models.ClientAuthnRequest{
				ClientIdPost:     expectedClientId,
				ClientSecretPost: "random_secret",
			},
			true,
		},
		{
			"valid_assertion",
			models.ClientAuthnRequest{
				ClientAssertion:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYW5kb21fY2xpZW50X2lkIn0.WH0vrq6CPaEzoORF1TklNqCziEGxwbfH4iPQWcdXYzgtm6iaxMRlk1fes7kb0VUAKuoJL650VZ5wTmn0HG-mL8f9PZ2pt7KWIx5QL8g1U42ZEcY2dDKdhmG9alcAVRUnV3dV5GlmBPD5k3X0bev7hfGXUA6OlzCCXpQ8NYOp02p9c0izucvJm75uOPK3snUzSCFIrewS8WrFUZuQ5TLSmMJGdcWoeMhcnf8rfWBR88RD_6L0bTugUNe9ILxTNZp0vsWCXcCfGuG2_nWekbWchTCMYSxQ-fA4OV5Zm5AvW2YOYPcx9FcoqZyVuDgUVwPXFV_UnZsXdYyZNS4mSfO0PQ",
				ClientAssertionType: constants.JWTBearerAssertion,
			},
			true,
		},
		{
			"client_id_post_can_be_sent_with_other_auth_params",
			models.ClientAuthnRequest{
				ClientIdBasicAuthn:     expectedClientId,
				ClientSecretBasicAuthn: "random_secret",
				ClientIdPost:           expectedClientId,
			},
			true,
		},
		{
			"assertion_without_issuer",
			models.ClientAuthnRequest{
				ClientAssertion:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJub19pc3MiOiJyYW5kb21fY2xpZW50X2lkIn0.Eh27TZ5JDjyty5OiyKXyxfWGnKdvl35VhCZygCyLZS3IjCVmkYLshndpAzSywZX5pUU1UCXlHRXNd3kLg5hPx4wEVgDpPhBWGhl_gNPogfZcwcWHjo_lxqzB6fOIOw_JzPwGivgKViIGZvJabuRcpgqOZ2-XSOPdRjB1o9z89k3nLVFnK_l8fHok0p43gPeQaIivMMHWV6IpN-rd7EeYKTNgmAbH_wu0B7UPqJ6v8pWJx9zlclg_DrbUuVDjcKt2_lTROFG5kcWBOij6vnE0GYcwoU91CBYCN82hj2DiiKchmVi-M3h_cqTci1zYirFmOnehkVelR4rAESr2VsNZ6Q",
				ClientAssertionType: constants.JWTBearerAssertion,
			},
			false,
		},
		{
			"cannot_mix_auth_params",
			models.ClientAuthnRequest{
				ClientIdBasicAuthn:     expectedClientId,
				ClientSecretBasicAuthn: "random_secret",
				ClientSecretPost:       "random_secret",
			},
			false,
		},
		{
			"different_client_ids",
			models.ClientAuthnRequest{
				ClientIdBasicAuthn:     expectedClientId,
				ClientSecretBasicAuthn: "random_secret",
				ClientIdPost:           "invalid_client_id",
			},
			false,
		},
	}

	for _, c := range cases {
		t.Run(
			c.Name,
			func(t *testing.T) {
				// Then.
				clientId, err := oauth.ValidateClientAuthnRequest(c.Req)

				// Assert.
				isValid := err == nil
				if isValid != c.ShouldBeValid {
					t.Errorf("expected: %v actual: %v", c.ShouldBeValid, isValid)
					return
				}

				if c.ShouldBeValid && clientId != expectedClientId {
					t.Errorf("expected: %s actual: %s", expectedClientId, clientId)
				}
			},
		)
	}
}

func TestValidateAuthorizationRequest(t *testing.T) {
	validClient := models.Client{
		Id:            "random_client_id",
		RedirectUris:  []string{"https://example.com"},
		Scopes:        []string{"scope1", "scope2", constants.OpenIdScope},
		GrantTypes:    constants.GrantTypes,
		ResponseTypes: constants.ResponseTypes,
		ResponseModes: constants.ResponseModes,
	}

	var cases = []struct {
		Name             string
		Req              models.AuthorizationRequest
		ClientModifyFunc func(client models.Client) models.Client
		ShouldBeValid    bool
	}{
		{
			"valid_oauth_request",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  validClient.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					ResponseMode: constants.QueryResponseMode,
					Scope:        validClient.Scopes[0],
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
		},
		{
			"valid_openid_request",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  validClient.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scope:        constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			true,
		},
		{
			"oauth_request_invalid_response_type",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  validClient.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scope:        constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				client.ResponseTypes = []constants.ResponseType{}
				return client
			},
			false,
		},
		{
			"oauth_request_missing_response_type",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri: validClient.RedirectUris[0],
					Scope:       constants.OpenIdScope,
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
		},
		{
			"oauth_request_invalid_scope",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  validClient.RedirectUris[0],
					ResponseType: constants.CodeResponse,
					Scope:        "invalid_scope",
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
		},
		{
			"oauth_request_invalid_redirect_uri",
			models.AuthorizationRequest{
				AuthorizationParameters: models.AuthorizationParameters{
					RedirectUri:  "https://invalid.com",
					ResponseType: constants.CodeResponse,
					Scope:        validClient.Scopes[0],
				},
			},
			func(client models.Client) models.Client {
				return client
			},
			false,
		},
	}

	for _, c := range cases {
		t.Run(
			c.Name,
			func(t *testing.T) {
				// Then.
				err := oauth.ValidateAuthorizationRequest(
					oauth.GetDummyContext(),
					c.Req,
					c.ClientModifyFunc(validClient),
				)

				// Assert.
				isValid := err == nil
				if isValid != c.ShouldBeValid {
					t.Errorf("expected: %v - actual: %v - error: %s", c.ShouldBeValid, isValid, err)
					return
				}

			},
		)
	}

}
