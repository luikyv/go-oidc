package federation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	clientID                string          = "https://client.testfed.com"
	intermediaryAuthorityID string          = "https://intermediary-authority.testfed.com"
	trustAnchorID           string          = "https://trust-anchor.testfed.com"
	trustMarkIssuerID       string          = "https://trust-mark-issuer.testfed.com"
	trustMarkCertification  goidc.TrustMark = "https://trust-mark-issuer.testfed.com/certification"
)

var (
	clientKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	clientJWK    = goidc.JSONWebKey{
		KeyID:     "client_key",
		Key:       clientKey,
		Algorithm: "RS256",
	}

	intermediaryAuthorityKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	intermediaryAuthorityJWK    = goidc.JSONWebKey{
		KeyID:     "intermediary_authority_key",
		Key:       intermediaryAuthorityKey,
		Algorithm: "RS256",
	}

	trustAnchorKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	trustAnchorJWK    = goidc.JSONWebKey{
		KeyID:     "trust_anchor_key",
		Key:       trustAnchorKey,
		Algorithm: "RS256",
	}

	trustMarkIssuerKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	trustMarkIssuerJWK    = goidc.JSONWebKey{
		KeyID:     "trust_mark_issuer_key",
		Key:       trustMarkIssuerKey,
		Algorithm: "RS256",
	}

	opKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	opJWK    = goidc.JSONWebKey{
		KeyID:     "op_key",
		Key:       opKey,
		Algorithm: "RS256",
	}
)

func TestClient(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		setup    func(*testing.T) oidc.Context
		validate func(*testing.T, *goidc.Client, error)
	}{
		{
			name:     "happy path",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				return setup(t, nil)
			},
			validate: func(t *testing.T, c *goidc.Client, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if c.ID != clientID {
					t.Errorf("client.ID = %s, want %s", c.ID, clientID)
				}
				if c.Federation == nil || c.Federation.TrustAnchor == "" {
					t.Error("the client is from a federation")
				}
			},
		},
		{
			name:     "required trust mark",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedRequiredClientTrustMarksFunc = func(_ context.Context, _ *goidc.Client) []goidc.TrustMark {
					return []goidc.TrustMark{trustMarkCertification}
				}
				return ctx
			},
			validate: func(t *testing.T, client *goidc.Client, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if client.ID != clientID {
					t.Errorf("client.ID = %s, want %s", client.ID, clientID)
				}
			},
		},
		{
			name:     "invalid trust mark signature",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss":  clientID,
							"sub":  clientID,
							"iat":  timeutil.TimestampNow(),
							"exp":  timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
							"metadata": map[string]any{
								"openid_relying_party": map[string]any{
									"client_registration_types": []string{"automatic", "explicit"},
								},
							},
							"authority_hints": []string{trustAnchorID},
							"trust_marks": []any{
								map[string]any{
									"trust_mark_type": trustMarkCertification,
									"trust_mark": oidctest.SignWithOptions(t, map[string]any{
										"trust_mark_type": trustMarkCertification,
										"iss":             trustMarkIssuerID,
										"sub":             clientID,
										"iat":             timeutil.TimestampNow(),
									}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark)),
								},
							},
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				ctx := setup(t, responses)
				ctx.OpenIDFedRequiredClientTrustMarksFunc = func(_ context.Context, _ *goidc.Client) []goidc.TrustMark {
					return []goidc.TrustMark{trustMarkCertification}
				}
				return ctx
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error is expected")
				}
			},
		},
		{
			name:     "invalid trust mark id",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss":  clientID,
							"sub":  clientID,
							"iat":  timeutil.TimestampNow(),
							"exp":  timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
							"metadata": map[string]any{
								"openid_relying_party": map[string]any{
									"client_registration_types": []string{"automatic", "explicit"},
								},
							},
							"authority_hints": []string{trustAnchorID},
							"trust_marks": []any{
								map[string]any{
									"trust_mark_type": trustMarkCertification,
									"trust_mark": oidctest.SignWithOptions(t, map[string]any{
										"trust_mark_type": "random_trust_mark_id",
										"iss":             trustMarkIssuerID,
										"sub":             clientID,
										"iat":             timeutil.TimestampNow(),
									}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark)),
								},
							},
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				ctx := setup(t, responses)
				ctx.OpenIDFedRequiredClientTrustMarksFunc = func(_ context.Context, _ *goidc.Client) []goidc.TrustMark {
					return []goidc.TrustMark{trustMarkCertification}
				}
				return ctx
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error is expected")
				}
			},
		},
		{
			name:     "invalid metadata policy",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					trustAnchorID + "/fetch?sub=" + url.QueryEscape(clientID): func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss":  trustAnchorID,
							"sub":  clientID,
							"iat":  timeutil.TimestampNow(),
							"exp":  timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
							"metadata_policy": map[string]any{
								"openid_relying_party": map[string]any{
									"token_endpoint_auth_method": map[string]any{"essential": true},
								},
							},
						}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
					clientID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss":  clientID,
							"sub":  clientID,
							"iat":  timeutil.TimestampNow(),
							"exp":  timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
							"metadata": map[string]any{
								"openid_relying_party": map[string]any{
									"client_registration_types": []string{"automatic", "explicit"},
								},
							},
							"authority_hints": []string{trustAnchorID},
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				return setup(t, responses)
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error is expected: essential field TokenAuthnMethod is not set")
				}
			},
		},
		{
			name:     "circular dependency",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					intermediaryAuthorityID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss":  intermediaryAuthorityID,
							"sub":  intermediaryAuthorityID,
							"iat":  timeutil.TimestampNow(),
							"exp":  timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{intermediaryAuthorityJWK.Public()}},
							"metadata": map[string]any{
								"federation_entity": map[string]any{
									"federation_fetch_endpoint": intermediaryAuthorityID + "/fetch",
								},
							},
							"authority_hints": []string{intermediaryAuthorityID},
						}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				return setup(t, responses)
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error is expected")
				}
				if !errors.Is(err, ErrCircularDependency) {
					t.Fatalf("error due to circular dependency is expected, got %v", err)
				}
			},
		},
		{
			name:     "client manager error",
			clientID: "non-url-client-that-does-not-exist",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit}
				return ctx
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error expected when client is not found and automatic registration is disabled")
				}
			},
		},
		{
			name:     "not openid client",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss": clientID,
							"sub": clientID,
							"iat": timeutil.TimestampNow(),
							"exp": timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{
								Keys: []jose.JSONWebKey{clientJWK.Public()},
							},
							"metadata": map[string]any{
								"federation_entity": map[string]any{},
							},
							"authority_hints": []string{trustAnchorID},
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				return setup(t, responses)
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error expected when entity is not an openid client")
				}
			},
		},
		{
			name:     "registration type not supported",
			clientID: clientID,
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss": clientID,
							"sub": clientID,
							"iat": timeutil.TimestampNow(),
							"exp": timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{
								Keys: []jose.JSONWebKey{clientJWK.Public()},
							},
							"metadata": map[string]any{
								"openid_relying_party": map[string]any{
									"client_registration_types": []string{"explicit"},
								},
							},
							"authority_hints": []string{trustAnchorID},
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				return setup(t, responses)
			},
			validate: func(t *testing.T, _ *goidc.Client, err error) {
				if err == nil {
					t.Fatal("error expected when client does not support automatic registration")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx := test.setup(t)

			// When.
			client, err := Client(ctx, test.clientID, nil)

			// Then.
			test.validate(t, client, err)
		})
	}
}

func TestExplicitRegistration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) (oidc.Context, func(oidc.Context) (string, error))
	}{
		{
			name: "trust chain provided",
			setup: func(t *testing.T) (oidc.Context, func(oidc.Context) (string, error)) {
				ctx, chain := setUpWithChain(t, nil)
				return ctx, func(ctx oidc.Context) (string, error) {
					chainStatements := make([]string, len(chain))
					for i, st := range chain {
						chainStatements[i] = st.Signed()
					}
					return registerChainStatements(ctx, chainStatements)
				}
			},
		},
		{
			name: "entity configuration provided",
			setup: func(t *testing.T) (oidc.Context, func(oidc.Context) (string, error)) {
				ctx := setup(t, nil)
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"aud": ctx.Issuer(),
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"metadata": map[string]any{
						"openid_relying_party": map[string]any{
							"client_registration_types":  []string{"automatic", "explicit"},
							"token_endpoint_auth_method": "client_secret_post",
						},
					},
					"authority_hints": []string{intermediaryAuthorityID},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return ctx, func(ctx oidc.Context) (string, error) {
					return registerEntityConfiguration(ctx, entityConfig)
				}
			},
		},
		{
			name: "entity configuration with trust chain header",
			setup: func(t *testing.T) (oidc.Context, func(oidc.Context) (string, error)) {
				ctx, chain := setUpWithChain(t, nil)
				chainStatements := make([]any, len(chain))
				for i, st := range chain {
					chainStatements[i] = st.Signed()
				}
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"aud": ctx.Issuer(),
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"metadata": map[string]any{
						"openid_relying_party": map[string]any{
							"client_registration_types":  []string{"automatic", "explicit"},
							"token_endpoint_auth_method": "client_secret_post",
						},
					},
					"authority_hints": []string{intermediaryAuthorityID},
				}, clientJWK, (&jose.SignerOptions{}).
					WithType(jwtTypeEntityStatement).
					WithHeader("trust_chain", chainStatements))
				return ctx, func(ctx oidc.Context) (string, error) {
					return registerEntityConfiguration(ctx, entityConfig)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, action := test.setup(t)

			// When.
			st, err := action(ctx)

			// Then.
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			claims, err := oidctest.SafeClaims(st, opJWK)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if claims["iss"] != ctx.Issuer() {
				t.Errorf("claims.iss = %s, want %s", claims["iss"], ctx.Issuer())
			}
			if claims["sub"] != clientID {
				t.Errorf("claims.sub = %s, want %s", claims["sub"], clientID)
			}
			if claims["trust_anchor"] != trustAnchorID {
				t.Errorf("claims.trust_anchor = %s, want %s", claims["trust_anchor"], trustAnchorID)
			}
		})
	}
}

func setUpWithChain(t *testing.T, overrideResps map[string]func() *http.Response) (oidc.Context, trustChain) {
	t.Helper()

	ctx := setup(t, overrideResps)
	_, chain, err := buildAndResolveTrustChain(ctx, clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return ctx, chain
}

func setup(t *testing.T, overrideResps map[string]func() *http.Response) oidc.Context {
	t.Helper()

	responses := map[string]func() *http.Response{
		clientID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": clientID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
				"metadata": map[string]any{
					"openid_relying_party": map[string]any{
						"client_registration_types":  []string{"automatic", "explicit"},
						"token_endpoint_auth_method": "client_secret_post",
					},
				},
				"authority_hints": []string{intermediaryAuthorityID},
				"trust_marks": []any{
					map[string]any{
						"trust_mark_type": trustMarkCertification,
						"trust_mark": oidctest.SignWithOptions(t, map[string]any{
							"trust_mark_type": trustMarkCertification,
							"iss":             trustMarkIssuerID,
							"sub":             clientID,
							"iat":             timeutil.TimestampNow(),
						}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark)),
					},
				},
			}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		intermediaryAuthorityID + "/.well-known/openid-federation": func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": intermediaryAuthorityID,
				"sub": intermediaryAuthorityID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{intermediaryAuthorityJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": intermediaryAuthorityID + "/fetch",
					},
				},
				"authority_hints": []string{trustAnchorID},
			}, intermediaryAuthorityJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		intermediaryAuthorityID + "/fetch?sub=" + url.QueryEscape(clientID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": intermediaryAuthorityID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
			}, intermediaryAuthorityJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[string]any{
					string(trustMarkCertification): []string{trustMarkIssuerID},
				},
			}, trustAnchorJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustMarkIssuerID + "/.well-known/openid-federation": func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustMarkIssuerID,
				"sub": trustMarkIssuerID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustMarkIssuerJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{},
				},
				"authority_hints": []string{trustAnchorID},
			}, trustMarkIssuerJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/fetch?sub=" + url.QueryEscape(intermediaryAuthorityID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": intermediaryAuthorityID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{intermediaryAuthorityJWK.Public()},
				},
			}, trustAnchorJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/fetch?sub=" + url.QueryEscape(trustMarkIssuerID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustMarkIssuerID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustMarkIssuerJWK.Public()},
				},
			}, trustAnchorJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{contentTypeEntityStatementJWT},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	maps.Copy(responses, overrideResps)

	ctx := oidctest.NewContext(t)
	ctx.OpenIDFedIsEnabled = true
	ctx.OpenIDFedManager = ctx.GrantManager.(goidc.OpenIDFedManager)
	ctx.OpenIDFedEndpoint = "/.well-known/openid-federation"
	ctx.OpenIDFedJWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{opJWK}}, nil
	}
	ctx.OpenIDFedAuthorityHints = []string{trustAnchorID}
	ctx.OpenIDFedTrustedAnchors = []string{trustAnchorID}
	ctx.OpenIDFedSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
	ctx.OpenIDFedDefaultSigAlg = goidc.RS256
	ctx.OpenIDFedTrustChainMaxDepth = 5
	ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeAutomatic, goidc.ClientRegistrationTypeExplicit}
	ctx.HTTPClientFunc = func(ctx context.Context) *http.Client {
		return &http.Client{
			Transport: &mockRoundTripper{
				T:         t,
				Responses: responses,
			},
		}
	}

	return ctx
}

type mockRoundTripper struct {
	T         testing.TB
	Responses map[string]func() *http.Response
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if f := m.Responses[req.URL.String()]; f != nil {
		return f(), nil
	}
	return nil, errors.ErrUnsupported
}

func TestFetchEntityStatement(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) oidc.Context
	}{
		{
			name: "non ok status",
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						return &http.Response{
							StatusCode: 404,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}
					},
				}
				return setup(t, responses)
			},
		},
		{
			name: "invalid content type",
			setup: func(t *testing.T) oidc.Context {
				responses := map[string]func() *http.Response{
					clientID + "/.well-known/openid-federation": func() *http.Response {
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{"application/json"}},
							Body:       io.NopCloser(bytes.NewBufferString("{}")),
						}
					},
				}
				return setup(t, responses)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx := test.setup(t)

			// When.
			_, err := fetchEntityConfiguration(ctx, clientID)

			// Then.
			if err == nil {
				t.Fatal("error expected")
			}
		})
	}
}

func TestParseEntityConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) (oidc.Context, string)
	}{
		{
			name: "empty authority hints",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":             clientID,
					"sub":             clientID,
					"iat":             timeutil.TimestampNow(),
					"exp":             timeutil.TimestampNow() + 600,
					"jwks":            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints": []string{},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "empty trust anchor hints",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":                clientID,
					"sub":                clientID,
					"iat":                timeutil.TimestampNow(),
					"exp":                timeutil.TimestampNow() + 600,
					"jwks":               jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints":    []string{trustAnchorID},
					"trust_anchor_hints": []string{},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "with metadata policy",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":             clientID,
					"sub":             clientID,
					"iat":             timeutil.TimestampNow(),
					"exp":             timeutil.TimestampNow() + 600,
					"jwks":            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints": []string{trustAnchorID},
					"metadata_policy": map[string]any{},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "with metadata policy critical",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":                  clientID,
					"sub":                  clientID,
					"iat":                  timeutil.TimestampNow(),
					"exp":                  timeutil.TimestampNow() + 600,
					"jwks":                 jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints":      []string{trustAnchorID},
					"metadata_policy_crit": []string{"custom_operator"},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "with constraints",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":             clientID,
					"sub":             clientID,
					"iat":             timeutil.TimestampNow(),
					"exp":             timeutil.TimestampNow() + 600,
					"jwks":            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints": []string{trustAnchorID},
					"constraints": map[string]any{
						"max_path_length": 0,
					},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "with source endpoint",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":             clientID,
					"sub":             clientID,
					"iat":             timeutil.TimestampNow(),
					"exp":             timeutil.TimestampNow() + 600,
					"jwks":            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"authority_hints": []string{trustAnchorID},
					"source_endpoint": "https://example.com/source",
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, signedStatement := test.setup(t)

			// When.
			_, err := parseEntityConfiguration(ctx, signedStatement, nil)

			// Then.
			if err == nil {
				t.Fatal("error expected")
			}
		})
	}
}

func TestParseEntityStatement(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) (oidc.Context, string)
	}{
		{
			name: "missing kid header",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"iat":  timeutil.TimestampNow(),
					"exp":  timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, goidc.JSONWebKey{
					Key:       clientKey,
					Algorithm: "RS256",
				}, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "invalid typ header",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"iat":  timeutil.TimestampNow(),
					"exp":  timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, clientJWK, (&jose.SignerOptions{}).WithType("JWT"))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "missing jwks",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "with trust anchor claim",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":          clientID,
					"sub":          clientID,
					"iat":          timeutil.TimestampNow(),
					"exp":          timeutil.TimestampNow() + 600,
					"jwks":         jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
					"trust_anchor": trustAnchorID,
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "missing iat",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"exp":  timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "missing exp",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"iat":  timeutil.TimestampNow(),
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "expired statement",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"iat":  timeutil.TimestampNow() - 1000,
					"exp":  timeutil.TimestampNow() - 500,
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "audience not allowed",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss":  clientID,
					"sub":  clientID,
					"iat":  timeutil.TimestampNow(),
					"exp":  timeutil.TimestampNow() + 600,
					"aud":  []string{"https://audience.example.com"},
					"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientJWK.Public()}},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "none algorithm",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
				}, goidc.JSONWebKey{
					KeyID:     "test_key",
					Key:       clientKey,
					Algorithm: "none",
				}, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "peer trust chain header not allowed",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, clientJWK, (&jose.SignerOptions{}).
					WithType(jwtTypeEntityStatement).
					WithHeader("peer_trust_chain", []string{"some_chain"}))
				return setup(t, nil), signedStatement
			},
		},
		{
			name: "trust chain header not allowed without explicit registration",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, clientJWK, (&jose.SignerOptions{}).
					WithType(jwtTypeEntityStatement).
					WithHeader("trust_chain", []string{"some_chain"}))
				return setup(t, nil), signedStatement
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, signedStatement := test.setup(t)

			// When.
			_, err := parseEntityConfiguration(ctx, signedStatement, nil)

			// Then.
			if err == nil {
				t.Fatal("error expected")
			}
		})
	}
}

func TestParseSubordinateStatement(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) (oidc.Context, string)
		assert func(*testing.T, entityStatement, error)
	}{
		{
			name: "with authority hints",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has authority_hints")
				}
			},
		},
		{
			name: "with trust anchor hints",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"trust_anchor_hints": []string{trustAnchorID},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has trust_anchor_hints")
				}
			},
		},
		{
			name: "with trust marks",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"trust_marks": []any{},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has trust_marks")
				}
			},
		},
		{
			name: "with trust mark issuers",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"trust_mark_issuers": map[string]any{},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has trust_mark_issuers")
				}
			},
		},
		{
			name: "with trust mark owners",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"trust_mark_owners": map[string]any{},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has trust_mark_owners")
				}
			},
		},
		{
			name: "with invalid metadata policy",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"metadata_policy": map[string]any{
						"openid_relying_party": map[string]any{
							"token_endpoint_auth_method": map[string]any{
								"value":  "private_key_jwt",
								"one_of": []string{"client_secret_basic"},
							},
						},
					},
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when subordinate statement has invalid metadata policy")
				}
			},
		},
		{
			name: "with source endpoint",
			setup: func(t *testing.T) (oidc.Context, string) {
				signedStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": intermediaryAuthorityID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"source_endpoint": "https://authority.example.com/fetch",
				}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), signedStatement
			},
			assert: func(t *testing.T, st entityStatement, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if st.SourceEndpoint != "https://authority.example.com/fetch" {
					t.Errorf("st.SourceEndpoint = %s, want %s", st.SourceEndpoint, "https://authority.example.com/fetch")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, signedStatement := test.setup(t)

			// When.
			st, err := parseSubordinateStatement(ctx, signedStatement, parseOptions{
				jwks:    goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{intermediaryAuthorityJWK.Public()}},
				issuer:  intermediaryAuthorityID,
				subject: clientID,
			})

			// Then.
			test.assert(t, st, err)
		})
	}
}

func TestParseTrustChain(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) (oidc.Context, []string)
		assert func(*testing.T, trustChain, error)
	}{
		{
			name: "too short",
			setup: func(t *testing.T) (oidc.Context, []string) {
				return setup(t, nil), []string{"single_statement"}
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected for trust chain with only one statement")
				}
			},
		},
		{
			name: "untrusted anchor",
			setup: func(t *testing.T) (oidc.Context, []string) {
				untrustedAnchorID := "https://untrusted-anchor.testfed.com"
				untrustedAnchorKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				untrustedAnchorJWK := goidc.JSONWebKey{
					KeyID:     "untrusted_key",
					Key:       untrustedAnchorKey,
					Algorithm: "RS256",
				}
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{untrustedAnchorID},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				anchorConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": untrustedAnchorID,
					"sub": untrustedAnchorID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{untrustedAnchorJWK.Public()},
					},
				}, untrustedAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), []string{entityConfig, anchorConfig}
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected for untrusted trust anchor")
				}
			},
		},
		{
			name: "invalid last statement",
			setup: func(t *testing.T) (oidc.Context, []string) {
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), []string{entityConfig, "invalid_jwt_token"}
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected for unparseable last statement in trust chain")
				}
			},
		},
		{
			name: "with trust anchor config in chain",
			setup: func(t *testing.T) (oidc.Context, []string) {
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				subordinateStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": trustAnchorID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
					},
					"metadata": map[string]any{
						"federation_entity": map[string]any{
							"federation_fetch_endpoint": trustAnchorID + "/fetch",
						},
					},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), []string{entityConfig, subordinateStatement, trustAnchorConfig}
			},
			assert: func(t *testing.T, chain trustChain, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(chain) != 3 {
					t.Errorf("chain length = %d, want 3", len(chain))
				}
			},
		},
		{
			name: "invalid subordinate statement",
			setup: func(t *testing.T) (oidc.Context, []string) {
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				invalidSubStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
					"authority_hints": []string{"some_hint"},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": trustAnchorID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
					},
					"metadata": map[string]any{
						"federation_entity": map[string]any{
							"federation_fetch_endpoint": trustAnchorID + "/fetch",
						},
					},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), []string{entityConfig, invalidSubStatement, trustAnchorConfig}
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected for invalid subordinate statement in trust chain")
				}
			},
		},
		{
			name: "subject mismatch",
			setup: func(t *testing.T) (oidc.Context, []string) {
				wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				wrongJWK := goidc.JSONWebKey{
					KeyID:     "wrong_key",
					Key:       wrongKey,
					Algorithm: "RS256",
				}
				entityConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": clientID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{wrongJWK.Public()},
					},
					"authority_hints": []string{trustAnchorID},
				}, wrongJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				subordinateStatement := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": clientID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{clientJWK.Public()},
					},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
					"iss": trustAnchorID,
					"sub": trustAnchorID,
					"iat": timeutil.TimestampNow(),
					"exp": timeutil.TimestampNow() + 600,
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
					},
					"metadata": map[string]any{
						"federation_entity": map[string]any{
							"federation_fetch_endpoint": trustAnchorID + "/fetch",
						},
					},
				}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
				return setup(t, nil), []string{entityConfig, subordinateStatement, trustAnchorConfig}
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected when entity config is signed with unauthorized key")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, chainStatements := test.setup(t)

			// When.
			chain, err := parseTrustChain(ctx, chainStatements)

			// Then.
			test.assert(t, chain, err)
		})
	}
}

func TestParseTrustMark_MissingKidHeader(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
	}, goidc.JSONWebKey{
		Key:       trustMarkIssuerKey,
		Algorithm: "RS256",
		// No KeyID.
	}, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark is missing kid header")
	}
}

func TestParseTrustMark_InvalidTypHeader(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType("JWT")) // Wrong type.

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark has invalid typ header")
	}
}

func TestParseTrustMark_MissingIat(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		// Missing iat.
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark is missing iat claim")
	}
}

func TestParseTrustMark_WrongSubject(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	wrongSubject := "https://wrong-subject.example.com"
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             wrongSubject, // Wrong subject.
		"iat":             timeutil.TimestampNow(),
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID, // Expected subject is different.
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark has wrong subject")
	}
}

func TestParseTrustMark_UnauthorizedIssuer(t *testing.T) {
	// Given: trust anchor has trust_mark_issuers but the issuer is not listed.
	unauthorizedIssuerID := "https://unauthorized-issuer.testfed.com"
	unauthorizedIssuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	unauthorizedIssuerJWK := goidc.JSONWebKey{
		KeyID:     "unauthorized_issuer_key",
		Key:       unauthorizedIssuerKey,
		Algorithm: "RS256",
	}

	responses := map[string]func() *http.Response{
		unauthorizedIssuerID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": unauthorizedIssuerID,
				"sub": unauthorizedIssuerID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{unauthorizedIssuerJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{},
				},
				"authority_hints": []string{trustAnchorID},
			}, unauthorizedIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
		trustAnchorID + "/fetch?sub=" + url.QueryEscape(unauthorizedIssuerID): func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": unauthorizedIssuerID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{unauthorizedIssuerJWK.Public()},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             unauthorizedIssuerID, // Not in trust_mark_issuers list.
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
	}, unauthorizedIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark issuer is not authorized")
	}
}

func TestFetchSubordinateStatement(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) (oidc.Context, entityStatement)
		assert func(*testing.T, entityStatement, error)
	}{
		{
			name: "not federation authority",
			setup: func(t *testing.T) (oidc.Context, entityStatement) {
				return setup(t, nil), entityStatement{
					Issuer: intermediaryAuthorityID,
					Metadata: metadata{
						FederationAuthority: nil,
					},
				}
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when authority is not a federation authority")
				}
			},
		},
		{
			name: "invalid fetch endpoint",
			setup: func(t *testing.T) (oidc.Context, entityStatement) {
				return setup(t, nil), entityStatement{
					Issuer: intermediaryAuthorityID,
					Metadata: metadata{
						FederationAuthority: &federationAuthority{
							FetchEndpoint: "://invalid-url",
						},
					},
				}
			},
			assert: func(t *testing.T, _ entityStatement, err error) {
				if err == nil {
					t.Fatal("error expected when fetch endpoint is invalid")
				}
			},
		},
		{
			name: "with private key jwt",
			setup: func(t *testing.T) (oidc.Context, entityStatement) {
				responses := map[string]func() *http.Response{
					intermediaryAuthorityID + "/fetch": func() *http.Response {
						st := oidctest.SignWithOptions(t, map[string]any{
							"iss": intermediaryAuthorityID,
							"sub": clientID,
							"iat": timeutil.TimestampNow(),
							"exp": timeutil.TimestampNow() + 600,
							"jwks": jose.JSONWebKeySet{
								Keys: []jose.JSONWebKey{clientJWK.Public()},
							},
						}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
							Body:       io.NopCloser(bytes.NewBufferString(st)),
						}
					},
				}
				ctx := setup(t, responses)
				authority := entityStatement{
					Issuer: intermediaryAuthorityID,
					JWKS:   goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{intermediaryAuthorityJWK.Public()}},
					Metadata: metadata{
						FederationAuthority: &federationAuthority{
							FetchEndpoint:                     intermediaryAuthorityID + "/fetch",
							FetchEndpointAuthMethods:          []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
							EndpointAuthSigAlgValuesSupported: []goidc.SignatureAlgorithm{goidc.RS256},
						},
					},
				}
				return ctx, authority
			},
			assert: func(t *testing.T, st entityStatement, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if st.Subject != clientID {
					t.Errorf("st.Subject = %s, want %s", st.Subject, clientID)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, authority := test.setup(t)

			// When.
			st, err := fetchSubordinateStatement(ctx, clientID, authority)

			// Then.
			test.assert(t, st, err)
		})
	}
}

func TestBuildTrustChain(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) (oidc.Context, entityStatement, bool)
		assert func(*testing.T, trustChain, error)
	}{
		{
			name: "no authority hints",
			setup: func(t *testing.T) (oidc.Context, entityStatement, bool) {
				return setup(t, nil), entityStatement{
					Subject:        clientID,
					AuthorityHints: nil,
				}, false
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected when entity has no authority hints")
				}
			},
		},
		{
			name: "max depth exceeded",
			setup: func(t *testing.T) (oidc.Context, entityStatement, bool) {
				ctx := setup(t, nil)
				ctx.OpenIDFedTrustChainMaxDepth = 1
				return ctx, entityStatement{}, true
			},
			assert: func(t *testing.T, _ trustChain, err error) {
				if err == nil {
					t.Fatal("error expected when trust chain depth is exceeded")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, entityConfig, callClient := test.setup(t)

			// When.
			var (
				chain trustChain
				err   error
			)
			if callClient {
				_, err = Client(ctx, clientID, nil)
			} else {
				chain, err = buildTrustChain(ctx, entityConfig)
			}

			// Then.
			test.assert(t, chain, err)
		})
	}
}

func TestRegister_NotOpenIDClient(t *testing.T) {
	// Given: entity has no openid_relying_party metadata.
	responses := map[string]func() *http.Response{
		clientID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": clientID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
				"metadata": map[string]any{
					// No openid_relying_party metadata.
					"federation_entity": map[string]any{},
				},
				"authority_hints": []string{trustAnchorID},
			}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setup(t, responses)

	// When.
	_, err := Client(ctx, clientID, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity is not an openid client")
	}
}

func TestRegister_RegistrationTypeNotSupported(t *testing.T) {
	// Given: client only supports explicit registration but we try automatic.
	responses := map[string]func() *http.Response{
		clientID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": clientID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
				"metadata": map[string]any{
					"openid_relying_party": map[string]any{
						"client_registration_types": []string{"explicit"}, // No automatic.
					},
				},
				"authority_hints": []string{trustAnchorID},
			}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setup(t, responses)

	// When.
	_, err := Client(ctx, clientID, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when client does not support automatic registration")
	}
}

func TestRegisterExplicitlyWithEntityConfiguration_WithTrustChainHeader(t *testing.T) {
	// Given: entity configuration with trust_chain header.
	ctx, chain := setUpWithChain(t, nil)
	chainStatements := make([]any, len(chain))
	for i, st := range chain {
		chainStatements[i] = st.Signed()
	}

	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": ctx.Issuer(),
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"metadata": map[string]any{
			"openid_relying_party": map[string]any{
				"client_registration_types":  []string{"automatic", "explicit"},
				"token_endpoint_auth_method": "client_secret_post",
			},
		},
		"authority_hints": []string{intermediaryAuthorityID},
	}, clientJWK, (&jose.SignerOptions{}).
		WithType(jwtTypeEntityStatement).
		WithHeader("trust_chain", chainStatements))

	// When.
	st, err := registerEntityConfiguration(ctx, entityConfig)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(st, opJWK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims["iss"] != ctx.Issuer() {
		t.Errorf("claims.iss = %s, want %s", claims["iss"], ctx.Issuer())
	}

	if claims["sub"] != clientID {
		t.Errorf("claims.sub = %s, want %s", claims["sub"], clientID)
	}

	if claims["trust_anchor"] != trustAnchorID {
		t.Errorf("claims.trust_anchor = %s, want %s", claims["trust_anchor"], trustAnchorID)
	}
}

func TestRegisterExplicitlyWithEntityConfiguration_InvalidEntityConfiguration(t *testing.T) {
	// Given: invalid entity configuration (missing required fields).
	ctx := setup(t, nil)
	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		// Missing iat, exp, jwks.
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	// When.
	_, err := registerEntityConfiguration(ctx, entityConfig)

	// Then.
	if err == nil {
		t.Fatal("error expected for invalid entity configuration")
	}
}

func TestRegisterExplicitlyWithChainStatements_InvalidChain(t *testing.T) {
	// Given: invalid chain (too short).
	ctx := setup(t, nil)
	chainStatements := []string{"single_statement"}

	// When.
	_, err := registerChainStatements(ctx, chainStatements)

	// Then.
	if err == nil {
		t.Fatal("error expected for invalid trust chain")
	}
}

func TestFetchEntityConfigurationJWKS(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) (oidc.Context, string)
		assert func(*testing.T, goidc.JSONWebKeySet, error)
	}{
		{
			name: "success",
			setup: func(t *testing.T) (oidc.Context, string) {
				return setup(t, nil), clientID
			},
			assert: func(t *testing.T, jwks goidc.JSONWebKeySet, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if len(jwks.Keys) == 0 {
					t.Error("expected at least one key in JWKS")
				}
			},
		},
		{
			name: "invalid entity",
			setup: func(t *testing.T) (oidc.Context, string) {
				return setup(t, nil), "https://nonexistent.example.com"
			},
			assert: func(t *testing.T, _ goidc.JSONWebKeySet, err error) {
				if err == nil {
					t.Fatal("error expected for nonexistent entity")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, entityID := test.setup(t)

			// When.
			jwks, err := FetchEntityConfigurationJWKS(ctx, entityID)

			// Then.
			test.assert(t, jwks, err)
		})
	}
}

func TestNewEntityConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) oidc.Context
		assert func(*testing.T, oidc.Context, map[string]any)
	}{
		{
			name: "jwks uri",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedJWKSRepresentations = []goidc.JWKSRepresentation{
					goidc.JWKSRepresentationURI,
				}
				return ctx
			},
			assert: func(t *testing.T, ctx oidc.Context, claims map[string]any) {
				if claims["iss"] != ctx.Issuer() {
					t.Errorf("claims.iss = %s, want %s", claims["iss"], ctx.Issuer())
				}
				if claims["sub"] != ctx.Issuer() {
					t.Errorf("claims.sub = %s, want %s", claims["sub"], ctx.Issuer())
				}
			},
		},
		{
			name: "signed jwks",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedJWKSRepresentations = []goidc.JWKSRepresentation{
					goidc.JWKSRepresentationSignedURI,
				}
				ctx.OpenIDFedSignedJWKSEndpoint = "/signed-jwks"
				return ctx
			},
			assert: func(t *testing.T, _ oidc.Context, claims map[string]any) {
				metadata, ok := claims["metadata"].(map[string]any)
				if !ok {
					t.Fatal("metadata claim expected")
				}
				opMetadata, ok := metadata["openid_provider"].(map[string]any)
				if !ok {
					t.Fatal("openid_provider metadata expected")
				}
				if opMetadata["signed_jwks_uri"] == nil {
					t.Error("signed_jwks_uri expected in openid_provider metadata")
				}
			},
		},
		{
			name: "inline jwks",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedJWKSRepresentations = []goidc.JWKSRepresentation{
					goidc.JWKSRepresentationInline,
				}
				return ctx
			},
			assert: func(t *testing.T, _ oidc.Context, claims map[string]any) {
				metadata, ok := claims["metadata"].(map[string]any)
				if !ok {
					t.Fatal("metadata claim expected")
				}
				opMetadata, ok := metadata["openid_provider"].(map[string]any)
				if !ok {
					t.Fatal("openid_provider metadata expected")
				}
				if opMetadata["jwks"] == nil {
					t.Error("jwks expected in openid_provider metadata")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx := test.setup(t)

			// When.
			st, err := newEntityConfiguration(ctx)

			// Then.
			if err != nil {
				t.Fatal(err)
			}
			claims, err := oidctest.SafeClaims(st, opJWK)
			if err != nil {
				t.Fatalf("unexpected error parsing entity configuration: %v", err)
			}
			test.assert(t, ctx, claims)
		})
	}
}

func TestSignedJWKS(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T) oidc.Context
		assert func(*testing.T, oidc.Context, map[string]any)
	}{
		{
			name: "with expiration",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedSignedJWKSLifetimeSecs = 3600
				return ctx
			},
			assert: func(t *testing.T, ctx oidc.Context, claims map[string]any) {
				if claims["iss"] != ctx.Issuer() {
					t.Errorf("claims.iss = %s, want %s", claims["iss"], ctx.Issuer())
				}
				if claims["keys"] == nil {
					t.Error("keys claim expected in signed JWKS")
				}
				if claims["exp"] == nil {
					t.Error("exp claim expected when lifetime is set")
				}
			},
		},
		{
			name: "no expiration",
			setup: func(t *testing.T) oidc.Context {
				ctx := setup(t, nil)
				ctx.OpenIDFedSignedJWKSLifetimeSecs = 0
				return ctx
			},
			assert: func(t *testing.T, _ oidc.Context, claims map[string]any) {
				if exp, ok := claims["exp"].(float64); ok && exp > 0 {
					t.Error("exp claim should not be set when lifetime is 0")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx := test.setup(t)

			// When.
			st, err := signedJWKS(ctx)

			// Then.
			if err != nil {
				t.Fatal(err)
			}
			claims, err := oidctest.SafeClaims(st, opJWK)
			if err != nil {
				t.Fatalf("unexpected error parsing signed JWKS: %v", err)
			}
			test.assert(t, ctx, claims)
		})
	}
}

func TestPrivateKeyJWTRequest(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	authority := entityStatement{
		Issuer: trustAnchorID,
		Metadata: metadata{
			FederationAuthority: &federationAuthority{
				EndpointAuthSigAlgValuesSupported: []goidc.SignatureAlgorithm{goidc.RS256},
			},
		},
	}

	// When.
	req, err := privateKeyJWTRequest(ctx, authority, "https://example.com/endpoint", url.Values{"param": {"value"}})

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if req.Method != http.MethodPost {
		t.Errorf("req.Method = %s, want POST", req.Method)
	}

	if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %s, want application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
	}
}

func TestUnauthenticatedRequest(t *testing.T) {
	// Given.
	ctx := setup(t, nil)

	// When.
	req, err := unauthenticatedRequest(ctx, "https://example.com/endpoint", url.Values{"param": {"value"}})

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if req.Method != http.MethodGet {
		t.Errorf("req.Method = %s, want GET", req.Method)
	}

	if !bytes.Contains([]byte(req.URL.String()), []byte("param=value")) {
		t.Error("query params expected in URL")
	}
}

func TestUnauthenticatedRequest_InvalidURI(t *testing.T) {
	// Given.
	ctx := setup(t, nil)

	// When.
	_, err := unauthenticatedRequest(ctx, "://invalid-uri", nil)

	// Then.
	if err == nil {
		t.Fatal("error expected for invalid URI")
	}
}

func TestParseTrustMark_InvalidAlgHeader(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
	}, goidc.JSONWebKey{
		KeyID:     "test_key",
		Key:       trustMarkIssuerKey,
		Algorithm: "none", // Invalid algorithm.
	}, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark has 'none' algorithm")
	}
}

func TestParseEntityStatement_NoneAlgorithm(t *testing.T) {
	// Given.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
	}, goidc.JSONWebKey{
		KeyID:     "test_key",
		Key:       clientKey,
		Algorithm: "none",
	}, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	ctx := setup(t, nil)

	// When.
	_, err := parseEntityConfiguration(ctx, signedStatement, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity statement uses 'none' algorithm")
	}
}

func TestParseEntityStatement_PeerTrustChainHeaderNotAllowed(t *testing.T) {
	// Given.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"authority_hints": []string{trustAnchorID},
	}, clientJWK, (&jose.SignerOptions{}).
		WithType(jwtTypeEntityStatement).
		WithHeader("peer_trust_chain", []string{"some_chain"}))

	ctx := setup(t, nil)

	// When.
	_, err := parseEntityConfiguration(ctx, signedStatement, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity statement contains peer_trust_chain header")
	}
}

func TestParseEntityStatement_TrustChainHeaderNotAllowedWithoutExplicitRegistration(t *testing.T) {
	// Given.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"authority_hints": []string{trustAnchorID},
	}, clientJWK, (&jose.SignerOptions{}).
		WithType(jwtTypeEntityStatement).
		WithHeader("trust_chain", []string{"some_chain"}))

	ctx := setup(t, nil)

	// When: parsing without explicitRegistration flag.
	_, err := parseEntityConfiguration(ctx, signedStatement, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity statement contains trust_chain header without explicit registration")
	}
}

func TestParseAuthorityConfiguration_NotFederationAuthority(t *testing.T) {
	// Given: entity configuration without federation_entity metadata.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"metadata": map[string]any{
			"openid_relying_party": map[string]any{},
		},
		"authority_hints": []string{trustAnchorID},
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	ctx := setup(t, nil)

	// When.
	_, err := parseAuthorityConfiguration(ctx, signedStatement)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity is not a federation authority")
	}
}

func TestParseSubordinateStatement_WithInvalidMetadataPolicy(t *testing.T) {
	// Given: subordinate statement with invalid metadata policy.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": intermediaryAuthorityID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"metadata_policy": map[string]any{
			"openid_relying_party": map[string]any{
				"token_endpoint_auth_method": map[string]any{
					"value":  "private_key_jwt",
					"one_of": []string{"client_secret_basic"}, // Conflicting operators.
				},
			},
		},
	}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	ctx := setup(t, nil)

	// When.
	_, err := parseSubordinateStatement(ctx, signedStatement, parseOptions{
		jwks:    goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{intermediaryAuthorityJWK}},
		issuer:  intermediaryAuthorityID,
		subject: clientID,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when subordinate statement has invalid metadata policy")
	}
}

func TestExtractRequiredTrustMarks_MissingRequiredMark(t *testing.T) {
	// Given.
	ctx := setup(t, nil)
	ctx.OpenIDFedRequiredClientTrustMarksFunc = func(_ context.Context, _ *goidc.Client) []goidc.TrustMark {
		return []goidc.TrustMark{goidc.TrustMark("https://non-existent.trust-mark.com/certification")}
	}
	config := entityStatement{
		Issuer:  clientID,
		Subject: clientID,
		TrustMarks: []trustMarkInfo{
			{Type: trustMarkCertification, TrustMark: "some_mark"},
		},
	}

	// When.
	_, err := extractRequiredTrustMarks(ctx, config, nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when required trust mark is missing")
	}
}

func TestParseTrustChain_InvalidLastStatement(t *testing.T) {
	// Given: trust chain with unparseable last statement.
	ctx := setup(t, nil)
	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	chainStatements := []string{entityConfig, "invalid_jwt_token"}

	// When.
	_, err := parseTrustChain(ctx, chainStatements)

	// Then.
	if err == nil {
		t.Fatal("error expected for unparseable last statement in trust chain")
	}
}

func TestParseTrustChain_WithTrustAnchorConfigInChain(t *testing.T) {
	// Given: trust chain where the trust anchor config is included.
	ctx := setup(t, nil)

	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"authority_hints": []string{trustAnchorID},
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	subordinateStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": trustAnchorID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
		},
		"metadata": map[string]any{
			"federation_entity": map[string]any{
				"federation_fetch_endpoint": trustAnchorID + "/fetch",
			},
		},
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	chainStatements := []string{entityConfig, subordinateStatement, trustAnchorConfig}

	// When.
	chain, err := parseTrustChain(ctx, chainStatements)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 3 {
		t.Errorf("chain length = %d, want 3", len(chain))
	}
}

func TestFetchSubordinateStatement_WithPrivateKeyJWT(t *testing.T) {
	// Given: authority that requires private_key_jwt authentication.
	responses := map[string]func() *http.Response{
		intermediaryAuthorityID + "/fetch": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": intermediaryAuthorityID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
			}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setup(t, responses)
	authority := entityStatement{
		Issuer: intermediaryAuthorityID,
		JWKS:   goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{intermediaryAuthorityJWK.Public()}},
		Metadata: metadata{
			FederationAuthority: &federationAuthority{
				FetchEndpoint:                     intermediaryAuthorityID + "/fetch",
				FetchEndpointAuthMethods:          []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
				EndpointAuthSigAlgValuesSupported: []goidc.SignatureAlgorithm{goidc.RS256},
			},
		},
	}

	// When.
	st, err := fetchSubordinateStatement(ctx, clientID, authority)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if st.Subject != clientID {
		t.Errorf("st.Subject = %s, want %s", st.Subject, clientID)
	}
}

func TestClient_ClientManagerError(t *testing.T) {
	// Given: non-URL client ID with automatic registration disabled.
	ctx := setup(t, nil)
	ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit}

	// When.
	_, err := Client(ctx, "non-url-client-that-does-not-exist", nil)

	// Then.
	if err == nil {
		t.Fatal("error expected when client is not found and automatic registration is disabled")
	}
}

func TestParseSubordinateStatement_WithSourceEndpoint(t *testing.T) {
	// Given: subordinate statement with valid source_endpoint.
	signedStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": intermediaryAuthorityID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"source_endpoint": "https://authority.example.com/fetch",
	}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	ctx := setup(t, nil)

	// When.
	st, err := parseSubordinateStatement(ctx, signedStatement, parseOptions{
		jwks:    goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{intermediaryAuthorityJWK.Public()}},
		issuer:  intermediaryAuthorityID,
		subject: clientID,
	})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if st.SourceEndpoint != "https://authority.example.com/fetch" {
		t.Errorf("st.SourceEndpoint = %s, want %s", st.SourceEndpoint, "https://authority.example.com/fetch")
	}
}

func TestParseTrustMark_WithDelegation(t *testing.T) {
	// Given: trust anchor with trust_mark_owners requiring delegation.
	trustMarkOwnerID := "https://trust-mark-owner.testfed.com"
	trustMarkOwnerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustMarkOwnerJWK := goidc.JSONWebKey{
		KeyID:     "trust_mark_owner_key",
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
	}

	delegation := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkOwnerID,
		"sub":             trustMarkIssuerID,
		"iat":             timeutil.TimestampNow(),
	}, trustMarkOwnerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMarkDelegation))

	responses := map[string]func() *http.Response{
		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[goidc.TrustMark]any{
					trustMarkCertification: []string{trustMarkIssuerID},
				},
				"trust_mark_owners": map[goidc.TrustMark]any{
					trustMarkCertification: map[string]any{
						"sub":  trustMarkOwnerID,
						"jwks": goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{trustMarkOwnerJWK.Public()}},
					},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
		"delegation":      delegation,
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	mark, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mark.Delegation == "" {
		t.Error("expected delegation in trust mark")
	}
}

func TestParseTrustMark_MissingDelegationWhenRequired(t *testing.T) {
	// Given: trust anchor with trust_mark_owners but trust mark has no delegation.
	trustMarkOwnerID := "https://trust-mark-owner.testfed.com"
	trustMarkOwnerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustMarkOwnerJWK := goidc.JSONWebKey{
		KeyID:     "trust_mark_owner_key",
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
	}

	responses := map[string]func() *http.Response{
		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[string]any{
					string(trustMarkCertification): []string{trustMarkIssuerID},
				},
				"trust_mark_owners": map[string]any{
					string(trustMarkCertification): map[string]any{
						"sub":  trustMarkOwnerID,
						"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{trustMarkOwnerJWK.Public()}},
					},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
		// Missing delegation.
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when delegation is required but missing")
	}
}

func TestParseTrustMark_InvalidDelegationKidHeader(t *testing.T) {
	// Given: trust mark with delegation that has no kid header.
	trustMarkOwnerID := "https://trust-mark-owner.testfed.com"
	trustMarkOwnerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustMarkOwnerJWK := goidc.JSONWebKey{
		KeyID:     "trust_mark_owner_key",
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
	}

	delegation := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkOwnerID,
		"sub":             trustMarkIssuerID,
		"iat":             timeutil.TimestampNow(),
	}, goidc.JSONWebKey{
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
		// No KeyID.
	}, (&jose.SignerOptions{}).WithType(jwtTypeTrustMarkDelegation))

	responses := map[string]func() *http.Response{
		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[string]any{
					string(trustMarkCertification): []string{trustMarkIssuerID},
				},
				"trust_mark_owners": map[string]any{
					string(trustMarkCertification): map[string]any{
						"sub":  trustMarkOwnerID,
						"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{trustMarkOwnerJWK.Public()}},
					},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
		"delegation":      delegation,
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when delegation is missing kid header")
	}
}

func TestParseTrustMark_InvalidDelegationType(t *testing.T) {
	// Given: trust mark with delegation that has wrong typ header.
	trustMarkOwnerID := "https://trust-mark-owner.testfed.com"
	trustMarkOwnerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustMarkOwnerJWK := goidc.JSONWebKey{
		KeyID:     "trust_mark_owner_key",
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
	}

	delegation := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkOwnerID,
		"sub":             trustMarkIssuerID,
		"iat":             timeutil.TimestampNow(),
	}, trustMarkOwnerJWK, (&jose.SignerOptions{}).WithType("JWT")) // Wrong type.

	responses := map[string]func() *http.Response{
		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[string]any{
					string(trustMarkCertification): []string{trustMarkIssuerID},
				},
				"trust_mark_owners": map[string]any{
					string(trustMarkCertification): map[string]any{
						"sub":  trustMarkOwnerID,
						"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{trustMarkOwnerJWK.Public()}},
					},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
		"delegation":      delegation,
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when delegation has wrong typ header")
	}
}

func TestParseTrustMark_DelegationWrongMarkType(t *testing.T) {
	// Given: trust mark with delegation that has wrong trust_mark_type.
	trustMarkOwnerID := "https://trust-mark-owner.testfed.com"
	trustMarkOwnerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	trustMarkOwnerJWK := goidc.JSONWebKey{
		KeyID:     "trust_mark_owner_key",
		Key:       trustMarkOwnerKey,
		Algorithm: "RS256",
	}

	delegation := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": "wrong_mark_type", // Wrong type.
		"iss":             trustMarkOwnerID,
		"sub":             trustMarkIssuerID,
		"iat":             timeutil.TimestampNow(),
	}, trustMarkOwnerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMarkDelegation))

	responses := map[string]func() *http.Response{
		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": trustAnchorID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
				},
				"metadata": map[string]any{
					"federation_entity": map[string]any{
						"federation_fetch_endpoint": trustAnchorID + "/fetch",
					},
				},
				"trust_mark_issuers": map[string]any{
					string(trustMarkCertification): []string{trustMarkIssuerID},
				},
				"trust_mark_owners": map[string]any{
					string(trustMarkCertification): map[string]any{
						"sub":  trustMarkOwnerID,
						"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{trustMarkOwnerJWK.Public()}},
					},
				},
			}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	ctx := setup(t, responses)
	signedMark := oidctest.SignWithOptions(t, map[string]any{
		"trust_mark_type": trustMarkCertification,
		"iss":             trustMarkIssuerID,
		"sub":             clientID,
		"iat":             timeutil.TimestampNow(),
		"delegation":      delegation,
	}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark))

	// When.
	_, err := parseTrustMark(ctx, signedMark, parseTrustMarkOptions{
		subject:  clientID,
		markType: trustMarkCertification,
	})

	// Then.
	if err == nil {
		t.Fatal("error expected when delegation has wrong trust_mark_type")
	}
}

func TestRegisterExplicitlyWithTrustChain_NoOpenIDClientMetadata(t *testing.T) {
	// Given: a valid chain structure but without openid_relying_party metadata.
	ctx := setup(t, nil)

	// Create a minimal valid chain with 2 elements (config + subordinate statement).
	invalidChain := trustChain{
		entityStatement{
			Issuer:    clientID,
			Subject:   clientID,
			ExpiresAt: timeutil.TimestampNow() + 600,
			JWKS:      goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{clientJWK.Public()}},
			Metadata: metadata{
				OpenIDClient: nil, // No OpenID client metadata.
			},
		},
		entityStatement{
			Issuer:    trustAnchorID,
			Subject:   clientID,
			ExpiresAt: timeutil.TimestampNow() + 600,
			JWKS:      goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{clientJWK.Public()}},
		},
		entityStatement{
			Issuer:    trustAnchorID,
			Subject:   trustAnchorID,
			ExpiresAt: timeutil.TimestampNow() + 600,
			JWKS:      goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{trustAnchorJWK.Public()}},
		},
	}

	// When.
	_, err := registerClientExplicitly(ctx, invalidChain)

	// Then.
	if err == nil {
		t.Fatal("error expected when chain has no OpenID client metadata")
	}
}

func TestFetchTrustMark_IssuerNotFederationAuthority(t *testing.T) {
	// Given: trust mark issuer is not a federation authority (no federation_entity metadata).
	responses := map[string]func() *http.Response{
		trustMarkIssuerID + "/.well-known/openid-federation": func() *http.Response {
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustMarkIssuerID,
				"sub": trustMarkIssuerID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{trustMarkIssuerJWK.Public()},
				},
				"metadata": map[string]any{
					"openid_relying_party": map[string]any{}, // Not a federation authority.
				},
				"authority_hints": []string{trustAnchorID},
			}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setup(t, responses)
	ctx.OpenIDFedTrustMarkConfigs = []goidc.TrustMarkConfig{
		{Mark: trustMarkCertification, Issuer: trustMarkIssuerID},
	}

	// When.
	_, err := newEntityConfiguration(ctx)

	// Then.
	if err == nil {
		t.Fatal("error expected when trust mark issuer is not a federation authority")
	}
}

func TestParseTrustChain_InvalidSubordinateStatement(t *testing.T) {
	// Given: trust chain with invalid subordinate statement.
	ctx := setup(t, nil)

	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"authority_hints": []string{trustAnchorID},
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	// Subordinate statement with authority_hints (not allowed).
	invalidSubStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()},
		},
		"authority_hints": []string{"some_hint"}, // Not allowed in subordinate statement.
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": trustAnchorID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
		},
		"metadata": map[string]any{
			"federation_entity": map[string]any{
				"federation_fetch_endpoint": trustAnchorID + "/fetch",
			},
		},
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	chainStatements := []string{entityConfig, invalidSubStatement, trustAnchorConfig}

	// When.
	_, err := parseTrustChain(ctx, chainStatements)

	// Then.
	if err == nil {
		t.Fatal("error expected for invalid subordinate statement in trust chain")
	}
}

func TestParseTrustChain_SubjectMismatch(t *testing.T) {
	// Given: trust chain where entity config is signed with unauthorized key.
	ctx := setup(t, nil)

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongJWK := goidc.JSONWebKey{
		KeyID:     "wrong_key",
		Key:       wrongKey,
		Algorithm: "RS256",
	}

	entityConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{wrongJWK.Public()}, // Different from what subordinate says.
		},
		"authority_hints": []string{trustAnchorID},
	}, wrongJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	subordinateStatement := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": clientID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{clientJWK.Public()}, // Subordinate authorizes a different key.
		},
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	trustAnchorConfig := oidctest.SignWithOptions(t, map[string]any{
		"iss": trustAnchorID,
		"sub": trustAnchorID,
		"iat": timeutil.TimestampNow(),
		"exp": timeutil.TimestampNow() + 600,
		"jwks": jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{trustAnchorJWK.Public()},
		},
		"metadata": map[string]any{
			"federation_entity": map[string]any{
				"federation_fetch_endpoint": trustAnchorID + "/fetch",
			},
		},
	}, trustAnchorJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	chainStatements := []string{entityConfig, subordinateStatement, trustAnchorConfig}

	// When.
	_, err := parseTrustChain(ctx, chainStatements)

	// Then.
	if err == nil {
		t.Fatal("error expected when entity config is signed with unauthorized key")
	}
}
