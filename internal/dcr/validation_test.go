package dcr

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateRequest(t *testing.T) {
	testCases := []struct {
		name                string
		modifiedClientFunc  func(goidc.Client) *goidc.Client
		modifiedContextFunc func(oidc.Context) *oidc.Context
		shouldBeValid       bool
	}{
		{
			"valid_client",
			func(c goidc.Client) *goidc.Client { return &c },
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			true,
		},
		{
			"invalid_authn_method",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = "invalid_authn"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_scope",
			func(c goidc.Client) *goidc.Client {
				c.ScopeIDs = "invalid_scope_id"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_private_key_jwt_sig_alg",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnPrivateKeyJWT
				c.AuthnSigAlg = "invalid_sig_alg"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"jwks_jwks_uri_is_required_for_private_key_jwt",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnPrivateKeyJWT
				c.PublicJWKS = nil
				c.PublicJWKSURI = ""
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"jwks_jwks_uri_is_required_for_self_signed_tls",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnSelfSignedTLS
				c.PublicJWKS = nil
				c.PublicJWKSURI = ""
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_secret_jwt_sig_alg",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnSecretJWT
				c.AuthnSigAlg = "invalid_sig_alg"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"valid_tls_authn",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnTLS
				c.TLSSubDistinguishedName = "example"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			true,
		},
		{
			"no_sub_identifier_for_tls_authn",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnTLS
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"more_than_one_sub_identifier_for_tls_authn",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnTLS
				c.TLSSubDistinguishedName = "example"
				c.TLSSubAlternativeName = "example"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_grant_type",
			func(c goidc.Client) *goidc.Client {
				c.GrantTypes = append(c.GrantTypes, "invalid_grant")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"none_authn_invalid_for_client_credentials",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnNone
				c.GrantTypes = append(c.GrantTypes, goidc.GrantClientCredentials)
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_authn_for_introspection",
			func(c goidc.Client) *goidc.Client {
				c.AuthnMethod = goidc.ClientAuthnSecretPost
				c.GrantTypes = append(c.GrantTypes, goidc.GrantIntrospection)
				return &c
			},
			func(ctx oidc.Context) *oidc.Context {
				ctx.IntrospectionClientAuthnMethods = []goidc.ClientAuthnType{
					goidc.ClientAuthnSecretBasic,
				}
				return &ctx
			},
			false,
		},
		{
			"invalid_redirect_uri",
			func(c goidc.Client) *goidc.Client {
				c.RedirectURIs = append(c.RedirectURIs, "invalid")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"redirect_uri_with_fragment",
			func(c goidc.Client) *goidc.Client {
				c.RedirectURIs = append(c.RedirectURIs, "https://example.com#fragment")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"redirect_uri_with_fragment",
			func(c goidc.Client) *goidc.Client {
				c.RedirectURIs = append(c.RedirectURIs, "https://example.com#fragment")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"invalid_response_type",
			func(c goidc.Client) *goidc.Client {
				c.ResponseTypes = append(c.ResponseTypes, "invalid")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"implicit_grant_is_required_for_implicit_response_type",
			func(c goidc.Client) *goidc.Client {
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeIDToken}
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"authz_code_grant_is_required_for_code_response_type",
			func(c goidc.Client) *goidc.Client {
				c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"valid_subject_identifier_type",
			func(c goidc.Client) *goidc.Client {
				c.SubIdentifierType = goidc.SubjectIdentifierPublic
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			true,
		},
		{
			"invalid_subject_identifier_type",
			func(c goidc.Client) *goidc.Client {
				c.SubIdentifierType = "invalid"
				return &c
			},
			func(ctx oidc.Context) *oidc.Context { return &ctx },
			false,
		},
		{
			"valid_auth_details",
			func(c goidc.Client) *goidc.Client {
				c.AuthDetailTypes = append(c.AuthDetailTypes, "type1")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context {
				ctx.AuthDetailsIsEnabled = true
				ctx.AuthDetailTypes = append(ctx.AuthDetailTypes, "type1")
				return &ctx
			},
			true,
		},
		{
			"invalid_auth_details",
			func(c goidc.Client) *goidc.Client {
				c.AuthDetailTypes = append(c.AuthDetailTypes, "invalid")
				return &c
			},
			func(ctx oidc.Context) *oidc.Context {
				ctx.AuthDetailsIsEnabled = true
				ctx.AuthDetailTypes = append(ctx.AuthDetailTypes, "type1")
				return &ctx
			},
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given.
			ctx := oidctest.NewContext(t)
			ctx = testCase.modifiedContextFunc(*ctx)

			validClient, _ := oidctest.NewClient(t)
			client := testCase.modifiedClientFunc(*validClient)
			req := request{
				ClientMetaInfo: client.ClientMetaInfo,
			}

			// When.
			err := validateRequest(ctx, req)

			// Then.
			isValid := err == nil
			if isValid != testCase.shouldBeValid {
				t.Fatalf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
			}

			if isValid {
				return
			}

			var oidcErr oidcerr.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("invalid error type")
			}

			if oidcErr.Code != oidcerr.CodeInvalidClientMetadata {
				t.Errorf("Code = %s, want %s", oidcErr.Code, oidcerr.CodeInvalidClientMetadata)
			}

		})
	}
}
