package dcr

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

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
			"valid_subject_identifier_type",
			func(c *goidc.Client) {
				c.SubIdentifierType = goidc.SubjectIdentifierPublic

			},
			func(ctx oidc.Context) {},
			true,
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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given.
			ctx := oidctest.NewContext(t)
			testCase.modifiedContextFunc(ctx)

			client, _ := oidctest.NewClient(t)
			testCase.modifiedClientFunc(client)

			// When.
			err := validate(ctx, &client.ClientMetaInfo)

			// Then.
			isValid := err == nil
			if isValid != testCase.shouldBeValid {
				t.Fatalf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
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
