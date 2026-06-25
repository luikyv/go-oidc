package client_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestResolve(t *testing.T) {
	tests := map[string]struct {
		setup    func() (oidc.Context, *client.Meta)
		wantErr  bool
		validate func(t *testing.T, c *client.Meta)
	}{

		"valid client": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"grant_types defaults to authorization_code": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = nil
				// Without grant types, response types that require implicit/authz-code
				// would fail later; clear them too so only defaults are exercised.
				c.ResponseTypes = nil
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if len(c.GrantTypes) != 1 || c.GrantTypes[0] != goidc.GrantAuthorizationCode {
					t.Errorf("got %v, want [authorization_code]", c.GrantTypes)
				}
			},
		},

		"response_types defaults to code": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ResponseTypes = nil
				// Keep only authorization_code grant to avoid implicit-requires-grant errors.
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if len(c.ResponseTypes) != 1 || c.ResponseTypes[0] != goidc.ResponseTypeCode {
					t.Errorf("got %v, want [code]", c.ResponseTypes)
				}
			},
		},

		"application_type defaults to web": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = ""
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.ApplicationType != goidc.ApplicationTypeWeb {
					t.Errorf("got %s, want web", c.ApplicationType)
				}
			},
		},

		"unsupported scope rejected": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ScopeIDs = "invalid_scope"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"openid scope required when server enforces it": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.OpenIDRequired = true
				c, _ := oidctest.NewClient(t)
				c.ScopeIDs = "scope1" // no openid
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"unsupported authn method": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = "invalid_authn"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"private_key_jwt requires jwks": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodPrivateKeyJWT
				c.JWKS = nil
				c.JWKSURI = ""
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"private_key_jwt accepts jwks_uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodPrivateKeyJWT
				c.JWKS = nil
				c.JWKSURI = "https://example.com/jwks"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"private_key_jwt unsupported sig alg": {
			// ctx.TokenAuthnPrivateKeyJWTSigAlgs is empty by default; any non-empty
			// value for TokenAuthnSigAlg will not be in the supported list.
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodPrivateKeyJWT
				c.TokenAuthnSigAlg = "invalid_alg"
				// sig alg is checked before the JWKS requirement, so no JWKS needed.
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"secret_jwt unsupported sig alg": {
			// ctx.TokenAuthnSecretJWTSigAlgs is empty by default.
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretJWT
				c.TokenAuthnSigAlg = "invalid_alg"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"self_signed_tls requires jwks": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSelfSignedTLS
				c.JWKS = nil
				c.JWKSURI = ""
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"tls_client_auth no identifier": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodTLS
				// No TLS subject identifier set.
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"tls_client_auth multiple identifiers": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodTLS
				c.TLSSubjectDistinguishedName = "cn=example"
				c.TLSSubjectAlternativeName = "example.com"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"tls_client_auth valid with dn": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodTLS
				c.TLSSubjectDistinguishedName = "cn=example"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"tls identifiers cleared for non-tls authn": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretPost
				c.TLSSubjectDistinguishedName = "cn=example"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.TLSSubjectDistinguishedName != "" {
					t.Errorf("got %q, want empty", c.TLSSubjectDistinguishedName)
				}
			},
		},

		// ── Introspection / revocation authn ────────────────────────────────────

		"introspection authn must match token authn": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.TokenIntrospectionEnabled = true
				c, _ := oidctest.NewClient(t)
				// c.TokenAuthnMethod is secret_post; introspection uses a different method.
				c.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"revocation authn must match token authn": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.TokenRevocationEnabled = true
				c, _ := oidctest.NewClient(t)
				c.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"introspection fields cleared when introspection disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.TokenIntrospectionEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost
				c.TokenIntrospectionAuthnSigAlg = goidc.PS256
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.TokenIntrospectionAuthnMethod != "" {
					t.Errorf("got %s, want empty", c.TokenIntrospectionAuthnMethod)
				}
				if c.TokenIntrospectionAuthnSigAlg != "" {
					t.Errorf("got %s, want empty", c.TokenIntrospectionAuthnSigAlg)
				}
			},
		},

		// ── Grant & response types ───────────────────────────────────────────────

		"unsupported grant type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, "invalid_grant")
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"client_credentials disallowed for public client": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"unsupported response type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ResponseTypes = append(c.ResponseTypes, "invalid_response_type")
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"implicit grant required for implicit response type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeIDToken}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"authorization_code grant required for code response type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		// ── Redirect URIs (RFC 6749, RFC 8252) ──────────────────────────────────

		"fragment in redirect uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.RedirectURIs = append(c.RedirectURIs, "https://example.com?q=1#frag")
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"native app: loopback ipv4 allowed": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://127.0.0.1/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"native app: loopback ipv6 allowed": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://[::1]/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"native app: localhost allowed when server permits": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.LocalhostRedirectURIEnabled = true
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://localhost/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"native app: localhost rejected by default": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://localhost/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"native app: private-use scheme allowed": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"com.example.app://cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"native app: non-loopback http rejected": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"http://example.com/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"native app: https claimed uri allowed": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.ApplicationType = goidc.ApplicationTypeNative
				c.RedirectURIs = []string{"https://example.com/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"web app: http redirect rejected": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				// ApplicationType defaults to web.
				c.RedirectURIs = []string{"http://example.com/cb"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"jwks and jwks_uri mutually exclusive": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				privateJWK := oidctest.PrivatePS256JWK(t, "key1", goidc.KeyUsageSignature)
				publicJWK := privateJWK.Public()
				c.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{publicJWK}}
				c.JWKSURI = "https://example.com/jwks"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"invalid jwk in jwks": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				// A private JWK is not a public key; IsPublic() returns false.
				privateJWK := oidctest.PrivatePS256JWK(t, "key1", goidc.KeyUsageSignature)
				c.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{privateJWK}}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"jar sig alg not supported": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.JAREnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				c, _ := oidctest.NewClient(t)
				c.JARSigAlg = goidc.PS256 // not in [RS256]
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"jar fields cleared when jar disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.JAREnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.JARSigAlg = goidc.RS256
				c.JARRequired = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.JARSigAlg != "" {
					t.Errorf("got %s, want empty", c.JARSigAlg)
				}
				if c.JARRequired {
					t.Errorf("got %v, want false", c.JARRequired)
				}
			},
		},

		"jar enc fields cleared when jar enc disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.JAREnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.PS256}
				// ctx.JAREncEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.JARKeyEncAlg = goidc.RSA_OAEP
				c.JARContentEncAlg = goidc.A256GCM
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.JARKeyEncAlg != "" {
					t.Errorf("got %s, want empty", c.JARKeyEncAlg)
				}
				if c.JARContentEncAlg != "" {
					t.Errorf("got %s, want empty", c.JARContentEncAlg)
				}
			},
		},

		"jarm fields cleared when jarm disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.JARMEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.JARMSigAlg = goidc.RS256
				c.JARMKeyEncAlg = goidc.RSA_OAEP
				c.JARMContentEncAlg = goidc.A256GCM
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.JARMSigAlg != "" {
					t.Errorf("got %s, want empty", c.JARMSigAlg)
				}
				if c.JARMKeyEncAlg != "" {
					t.Errorf("got %s, want empty", c.JARMKeyEncAlg)
				}
				if c.JARMContentEncAlg != "" {
					t.Errorf("got %s, want empty", c.JARMContentEncAlg)
				}
			},
		},

		"jarm sig alg not supported": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.JARMEnabled = true
				ctx.JARMSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				c, _ := oidctest.NewClient(t)
				c.JARMSigAlg = goidc.PS256 // not in [RS256]
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		// ── ID token encryption ──────────────────────────────────────────────────

		"id token enc requires key enc alg when enc alg set": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.IDTokenEncEnabled = true
				c, _ := oidctest.NewClient(t)
				// Set content enc alg without key enc alg.
				c.IDTokenContentEncAlg = goidc.A256GCM
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"id token enc fields cleared when enc disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.IDTokenEncEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.IDTokenKeyEncAlg = goidc.RSA_OAEP
				c.IDTokenContentEncAlg = goidc.A256GCM
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.IDTokenKeyEncAlg != "" {
					t.Errorf("got %s, want empty", c.IDTokenKeyEncAlg)
				}
				if c.IDTokenContentEncAlg != "" {
					t.Errorf("got %s, want empty", c.IDTokenContentEncAlg)
				}
			},
		},

		"unsupported auth detail type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1"}
				c, _ := oidctest.NewClient(t)
				c.AuthDetailTypes = []goidc.AuthDetailType{"invalid_type"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"auth detail types cleared when rar disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.RAREnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.AuthDetailTypes = []goidc.AuthDetailType{"type1"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.AuthDetailTypes != nil {
					t.Errorf("got %v, want nil", c.AuthDetailTypes)
				}
			},
		},

		// ── Feature flag clearing ────────────────────────────────────────────────

		"dpop binding cleared when dpop disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.DPoPEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.DPoPTokenBindingRequired = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.DPoPTokenBindingRequired {
					t.Errorf("got %v, want false", c.DPoPTokenBindingRequired)
				}
			},
		},

		"tls binding cleared when mtls disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.MTLSEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.TLSTokenBindingRequired = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.TLSTokenBindingRequired {
					t.Errorf("got %v, want false", c.TLSTokenBindingRequired)
				}
			},
		},

		"post logout uris cleared when logout disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.LogoutEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.PostLogoutRedirectURIs = []string{"https://example.com/logout"}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.PostLogoutRedirectURIs != nil {
					t.Errorf("got %v, want nil", c.PostLogoutRedirectURIs)
				}
			},
		},

		"post logout uris validated when logout enabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.LogoutEnabled = true
				c, _ := oidctest.NewClient(t)
				c.PostLogoutRedirectURIs = []string{"http://example.com/logout"} // not https
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"credential offer endpoint cleared when vc disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.VCIEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.CredentialOfferEndpoint = "https://example.com/offer"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.CredentialOfferEndpoint != "" {
					t.Errorf("got %q, want empty", c.CredentialOfferEndpoint)
				}
			},
		},

		"par required cleared when par disabled": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// ctx.PAREnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.PARRequired = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.PARRequired {
					t.Errorf("got %v, want false", c.PARRequired)
				}
			},
		},

		// ── Subject identifier ───────────────────────────────────────────────────

		"unsupported subject identifier type": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.SubIdentifierType = "invalid"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"pairwise with single-host redirect uris valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{
					goidc.SubIdentifierPublic,
					goidc.SubIdentifierPairwise,
				}
				c, _ := oidctest.NewClient(t)
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.RedirectURIs = []string{
					"https://example.com/cb1",
					"https://example.com/cb2",
				}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"pairwise with multi-host redirect uris invalid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{
					goidc.SubIdentifierPublic,
					goidc.SubIdentifierPairwise,
				}
				c, _ := oidctest.NewClient(t)
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.RedirectURIs = []string{
					"https://example.com/cb",
					"https://other.com/cb",
				}
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"pairwise with sector identifier uri valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{
					goidc.SubIdentifierPublic,
					goidc.SubIdentifierPairwise,
				}
				c, _ := oidctest.NewClient(t)

				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, _ := json.Marshal(c.RedirectURIs)
					_, _ = w.Write(data)
				}))
				t.Cleanup(srv.Close)
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = srv.URL
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"pairwise redirect uris must be in sector identifier uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{
					goidc.SubIdentifierPublic,
					goidc.SubIdentifierPairwise,
				}
				c, _ := oidctest.NewClient(t)
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Serve a different redirect URI than the client's.
					data, _ := json.Marshal([]string{"https://unrelated.example.com/cb"})
					_, _ = w.Write(data)
				}))
				t.Cleanup(srv.Close)
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = srv.URL
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba delivery mode required": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				// CIBATokenDeliveryMode not set.
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba delivery mode not supported": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = "invalid_mode"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba notification endpoint required for ping/push": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
				// CIBANotificationEndpoint not set.
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba notification endpoint must be https": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
				c.CIBANotificationEndpoint = "http://example.com/notify" // not https
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		// This test replaces the incorrect TestResolve_InvalidCIBAUserCode: when the
		// server does not support user codes, the flag must be cleared (not rejected).
		"ciba user code cleared when server disallows": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				// ctx.CIBAUserCodeEnabled is false by default.
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				c.CIBAUserCodeEnabled = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.CIBAUserCodeEnabled {
					t.Errorf("got %v, want false (server does not support user codes)", c.CIBAUserCodeEnabled)
				}
			},
		},

		"ciba jar sig alg not supported": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				ctx.CIBAJAREnabled = true
				ctx.CIBAJARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				c.CIBAJARSigAlg = goidc.PS256 // not in [RS256]
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba fields cleared when grant absent": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				// CIBA not enabled in ctx.GrantTypes.
				c, _ := oidctest.NewClient(t)
				// Client does not request CIBA either but has stale CIBA metadata.
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				c.CIBANotificationEndpoint = "https://example.com/notify"
				c.CIBAJARSigAlg = goidc.RS256
				c.CIBAUserCodeEnabled = true
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.CIBATokenDeliveryMode != "" {
					t.Errorf("got %s, want empty", c.CIBATokenDeliveryMode)
				}
				if c.CIBANotificationEndpoint != "" {
					t.Errorf("got %q, want empty", c.CIBANotificationEndpoint)
				}
				if c.CIBAJARSigAlg != "" {
					t.Errorf("got %s, want empty", c.CIBAJARSigAlg)
				}
				if c.CIBAUserCodeEnabled {
					t.Errorf("got %v, want false", c.CIBAUserCodeEnabled)
				}
			},
		},

		"ciba none authn method rejected": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePoll,
				}
				c, _ := oidctest.NewClient(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"ciba poll valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"ciba ping valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
				c.CIBANotificationEndpoint = "https://example.com/notify"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"ciba push valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
				ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
					goidc.CIBADeliveryModePing,
					goidc.CIBADeliveryModePoll,
					goidc.CIBADeliveryModePush,
				}
				c, _ := oidctest.NewClient(t)
				c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePush
				c.CIBANotificationEndpoint = "https://example.com/notify"
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		// ── URL validations ──────────────────────────────────────────────────────

		"invalid logo_uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.LogoURI = "http://example.com/logo" // not https
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"invalid policy_uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.PolicyURI = "http://example.com/policy" // not https
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"invalid tos_uri": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.TermsOfServiceURI = "http://example.com/tos" // not https
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		// ── DefaultMaxAgeSecs ────────────────────────────────────────────────────

		"negative default_max_age rejected": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.DefaultMaxAgeSecs = oidctest.PointerOf(-1)
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: true,
		},

		"zero default_max_age valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.DefaultMaxAgeSecs = oidctest.PointerOf(0)
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		"positive default_max_age valid": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				c, _ := oidctest.NewClient(t)
				c.DefaultMaxAgeSecs = oidctest.PointerOf(3600)
				return ctx, &client.Meta{ClientMeta: c.ClientMeta}
			},
		},

		// ── RPMetadataChoices ────────────────────────────────────────────────────
		// ctx.IDTokenSigAlgs = [PS256] from oidctest.NewContext.

		"choice resolved to first server-supported value": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.RPMetadataChoicesEnabled = true
				c, _ := oidctest.NewClient(t)
				cc := &client.Meta{ClientMeta: c.ClientMeta}
				// Offer PS256 as the choices list; server supports PS256.
				cc.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.PS256}
				return ctx, cc
			},
			validate: func(t *testing.T, c *client.Meta) {
				if c.IDTokenSigAlg != goidc.PS256 {
					t.Errorf("got %s, want PS256", c.IDTokenSigAlg)
				}
			},
		},

		"current value must be in choices list": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.RPMetadataChoicesEnabled = true
				c, _ := oidctest.NewClient(t)
				cc := &client.Meta{ClientMeta: c.ClientMeta}
				// Current is PS256 but choices list only contains RS256.
				cc.IDTokenSigAlg = goidc.PS256
				cc.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				return ctx, cc
			},
			wantErr: true,
		},

		"no supported choice returns error": {
			setup: func() (oidc.Context, *client.Meta) {
				ctx := oidctest.NewContext(t)
				ctx.RPMetadataChoicesEnabled = true
				// ctx.IDTokenSigAlgs = [PS256]; client offers only RS256.
				c, _ := oidctest.NewClient(t)
				cc := &client.Meta{ClientMeta: c.ClientMeta}
				cc.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				return ctx, cc
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Given.
			ctx, c := test.setup()

			// When.
			err := client.Resolve(ctx, c)

			// Then.
			if gotErr := (err != nil); gotErr != test.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, test.wantErr)
			}

			if test.wantErr {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
					t.Fatalf("got %v, want error code %s", err, goidc.ErrorCodeInvalidClientMetadata)
				}
			}

			if test.validate != nil {
				test.validate(t, c)
			}
		})
	}
}
