package dcr

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TODO: Split this.
func TestValidateRequest(t *testing.T) {
	testCases := []struct {
		name                string
		modifiedClientFunc  func(*goidc.Client)
		modifiedContextFunc func(oidc.Context)
		shouldBeValid       bool
	}{
		{
			"valid_client",
			func(c *goidc.Client) {},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"invalid_authn_method",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = "invalid_authn"
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_scope",
			func(c *goidc.Client) {
				c.ScopeIDs = "invalid_scope_id"
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_private_key_jwt_sig_alg",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnPrivateKeyJWT
				c.TokenAuthnSigAlg = "invalid_sig_alg"
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"jwks_jwks_uri_is_required_for_private_key_jwt",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnPrivateKeyJWT
				c.PublicJWKS = nil
				c.PublicJWKSURI = ""
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"jwks_jwks_uri_is_required_for_self_signed_tls",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnSelfSignedTLS
				c.PublicJWKS = nil
				c.PublicJWKSURI = ""
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_secret_jwt_sig_alg",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnSecretJWT
				c.TokenAuthnSigAlg = "invalid_sig_alg"
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"valid_tls_authn",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnTLS
				c.TLSSubDistinguishedName = "example"
			},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"no_sub_identifier_for_tls_authn",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnTLS
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"more_than_one_sub_identifier_for_tls_authn",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnTLS
				c.TLSSubDistinguishedName = "example"
				c.TLSSubAlternativeName = "example"

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_grant_type",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, "invalid_grant")
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"none_authn_invalid_for_client_credentials",
			func(c *goidc.Client) {
				c.TokenAuthnMethod = goidc.ClientAuthnNone
				c.GrantTypes = append(c.GrantTypes, goidc.GrantClientCredentials)
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_authn_for_introspection",
			func(c *goidc.Client) {
				c.TokenIntrospectionAuthnMethod = goidc.ClientAuthnSecretPost
			},
			func(ctx oidc.Context) {
				ctx.TokenIntrospectionAuthnMethods = []goidc.ClientAuthnType{
					goidc.ClientAuthnSecretBasic,
				}
			},
			false,
		},
		{
			"invalid_redirect_uri",
			func(c *goidc.Client) {
				c.RedirectURIs = append(c.RedirectURIs, "invalid")

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"redirect_uri_with_fragment",
			func(c *goidc.Client) {
				c.RedirectURIs = append(c.RedirectURIs, "https://example.com?param=value#fragment")

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"invalid_response_type",
			func(c *goidc.Client) {
				c.ResponseTypes = append(c.ResponseTypes, "invalid")

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"implicit_grant_is_required_for_implicit_response_type",
			func(c *goidc.Client) {
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeIDToken}

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"authz_code_grant_is_required_for_code_response_type",
			func(c *goidc.Client) {
				c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}

			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"valid_public_subject_identifier_type",
			func(c *goidc.Client) {
				c.SubIdentifierType = goidc.SubIdentifierPublic
			},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"valid_pairwise_subject_identifier_type",
			func(c *goidc.Client) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, _ := json.Marshal(c.RedirectURIs)
					if _, err := w.Write(data); err != nil {
						t.Fatal(err)
					}
				}))

				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = server.URL
			},
			func(ctx oidc.Context) {
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
			},
			true,
		},
		{
			"valid_pairwise_subject_identifier_type_with_no_sector_uri",
			func(c *goidc.Client) {
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.RedirectURIs = []string{"https://example.com/test1", "https://example.com/test2"}
			},
			func(ctx oidc.Context) {
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
			},
			true,
		},
		{
			"invalid_pairwise_subject_identifier_no_sector_uri_and_redirect_uris_with_multiple_hosts",
			func(c *goidc.Client) {
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.RedirectURIs = []string{"https://example1.com", "https://example.com2"}
			},
			func(ctx oidc.Context) {
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
			},
			false,
		},
		{
			"invalid_redirect_uris_not_present_when_fetching_sector_identifier_uri",
			func(c *goidc.Client) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, _ := json.Marshal([]string{"https://random-redirect-uri-123.com"})
					if _, err := w.Write(data); err != nil {
						t.Fatal(err)
					}
				}))

				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = server.URL
			},
			func(ctx oidc.Context) {
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
			},
			false,
		},
		{
			"invalid_subject_identifier_type",
			func(c *goidc.Client) {
				c.SubIdentifierType = "invalid"
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"valid_auth_details",
			func(c *goidc.Client) {
				c.AuthDetailTypes = append(c.AuthDetailTypes, "type1")
			},
			func(ctx oidc.Context) {
				ctx.AuthDetailsIsEnabled = true
				ctx.AuthDetailTypes = append(ctx.AuthDetailTypes, "type1")
			},
			true,
		},
		{
			"invalid_auth_details",
			func(c *goidc.Client) {
				c.AuthDetailTypes = append(c.AuthDetailTypes, "invalid")
			},
			func(ctx oidc.Context) {
				ctx.AuthDetailsIsEnabled = true
				ctx.AuthDetailTypes = append(ctx.AuthDetailTypes, "type1")
			},
			false,
		},
		{
			"valid_ciba_ping",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePing
				c.CIBANotificationEndpoint = "https://example.com"
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
			},
			true,
		},
		{
			"valid_ciba_push",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePush
				c.CIBANotificationEndpoint = "https://example.com"
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
			},
			true,
		},
		{
			"valid_ciba_poll",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
			},
			true,
		},
		{
			"valid_ciba_jar",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll
				c.CIBAJARSigAlg = goidc.RS256
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
				ctx.CIBAJARIsEnabled = true
				ctx.CIBAJARSigAlgs = append(ctx.CIBAJARSigAlgs, goidc.RS256)
			},
			true,
		},
		{
			"invalid_ciba_jar",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll
				c.CIBAJARSigAlg = goidc.PS256
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
				ctx.CIBAJARIsEnabled = true
				ctx.CIBAJARSigAlgs = append(ctx.CIBAJARSigAlgs, goidc.RS256)
			},
			false,
		},
		{
			"valid_ciba_user_code",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll
				c.CIBAUserCodeIsEnabled = true
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
				ctx.CIBAUserCodeIsEnabled = true
			},
			true,
		},
		{
			"invalid_ciba_delivery_mode",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = "invalid_mode"
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
			},
			false,
		},
		{
			"invalid_ciba_user_code",
			func(c *goidc.Client) {
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll
				c.CIBAUserCodeIsEnabled = true
			},
			func(ctx oidc.Context) {
				ctx.CIBAIsEnabled = true
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
					goidc.CIBATokenDeliveryModePing,
					goidc.CIBATokenDeliveryModePoll,
					goidc.CIBATokenDeliveryModePush,
				}
			},
			false,
		},
		// RFC 8252 - OAuth 2.0 for Native Apps tests
		{
			"rfc8252_native_app_loopback_ipv4",
			func(c *goidc.Client) {
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://127.0.0.1/callback"}
			},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"rfc8252_native_app_loopback_ipv6",
			func(c *goidc.Client) {
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://[::1]/callback"}
			},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"rfc8252_native_app_private_use_uri_scheme",
			func(c *goidc.Client) {
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"com.example.app://callback"}
			},
			func(ctx oidc.Context) {},
			true,
		},
		{
			"rfc8252_web_app_loopback_rejected",
			func(c *goidc.Client) {
				c.ApplicationType = goidc.ApplicationTypeWeb
				c.RedirectURIs = []string{"http://127.0.0.1/callback"}
			},
			func(ctx oidc.Context) {},
			false,
		},
		{
			"rfc8252_native_app_non_loopback_http_rejected",
			func(c *goidc.Client) {
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://example.com/callback"}
			},
			func(ctx oidc.Context) {},
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given.
			ctx := oidctest.NewContext(t)
			testCase.modifiedContextFunc(ctx)

			client, _ := oidctest.NewClient(t)
			testCase.modifiedClientFunc(client)

			// When.
			err := validate(ctx, &client.ClientMeta)

			// Then.
			isValid := err == nil
			if !isValid {
				t.Log(err)
			}

			if isValid != testCase.shouldBeValid {
				t.Errorf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
			}

			if isValid {
				return
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("invalid error type")
			}

			if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
				t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
			}

		})
	}
}
