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
	clientID                string = "https://client.testfed.com"
	intermediaryAuthorityID string = "https://intermediary-authority.testfed.com"
	trustAnchorID           string = "https://trust-anchor.testfed.com"
	trustMarkIssuerID       string = "https://trust-mark-issuer.testfed.com"
	trustMarkCertification  string = trustMarkIssuerID + "/certification"
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
	// Given.
	ctx := setUp(t, nil)

	// When.
	client, err := Client(ctx, clientID)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if client.ID != clientID {
		t.Errorf("client.ID = %s, want %s", client.ID, clientID)
	}

	if !client.IsFederated {
		t.Error("the client is from a federation")
	}
}

func TestClient_TrustMark(t *testing.T) {
	// Given.
	ctx := setUp(t, nil)
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context, _ *goidc.Client) []string {
		return []string{trustMarkCertification}
	}

	// When.
	client, err := Client(ctx, clientID)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if client.ID != clientID {
		t.Errorf("client.ID = %s, want %s", client.ID, clientID)
	}
}

func TestClient_InvalidTrustMarkSignature(t *testing.T) {
	// Given.
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
					"openid_relying_party": map[string]any{},
				},
				"authority_hints": []string{trustAnchorID},
				"trust_marks": []any{
					map[string]any{
						"id": trustMarkCertification,
						"trust_mark": oidctest.SignWithOptions(t, map[string]any{
							"trust_mark_id": trustMarkCertification,
							"iss":           trustMarkIssuerID,
							"sub":           clientID,
							"iat":           timeutil.TimestampNow(),
						}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeTrustMark)),
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
	}
	ctx := setUp(t, responses)
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context, _ *goidc.Client) []string {
		return []string{trustMarkCertification}
	}

	// When.
	_, err := Client(ctx, clientID)

	// Then.
	if err == nil {
		t.Fatal("error is expected")
	}
}

func TestClient_InvalidTrustMarkID(t *testing.T) {
	// Given.
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
					"openid_relying_party": map[string]any{},
				},
				"authority_hints": []string{trustAnchorID},
				"trust_marks": []any{
					map[string]any{
						"id": trustMarkCertification,
						"trust_mark": oidctest.SignWithOptions(t, map[string]any{
							"trust_mark_id": "random_trust_mark_id",
							"iss":           trustMarkIssuerID,
							"sub":           clientID,
							"iat":           timeutil.TimestampNow(),
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
	}
	ctx := setUp(t, responses)
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context, _ *goidc.Client) []string {
		return []string{trustMarkCertification}
	}

	// When.
	_, err := Client(ctx, clientID)

	// Then.
	if err == nil {
		t.Fatal("error is expected")
	}
}

func TestClient_InvalidMetadataPolicy(t *testing.T) {
	// Given.
	responses := map[string]func() *http.Response{
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
				"metadata_policy": map[string]any{
					"openid_relying_party": map[string]any{
						"client_name": map[string]any{
							"essential": true,
						},
					},
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
	}
	ctx := setUp(t, responses)

	// When.
	_, err := Client(ctx, clientID)

	// Then.
	if err == nil {
		t.Fatal("error is expected")
	}
}

func TestClient_CircularDependency(t *testing.T) {
	// Given.
	intermediaryAuthorityID := "https://intermediary-authority.testfed.com"
	responses := map[string]func() *http.Response{
		intermediaryAuthorityID + "/.well-known/openid-federation": func() *http.Response {
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
				"authority_hints": []string{intermediaryAuthorityID},
			}, intermediaryAuthorityJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{contentTypeEntityStatementJWT}},
				Body:       io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setUp(t, responses)

	// When.
	_, err := Client(ctx, clientID)

	// Then.
	if err == nil {
		t.Fatal("error is expected")
	}

	if !errors.Is(err, ErrCircularDependency) {
		t.Fatalf("error due to circular dependency is expected, got %v", err)
	}
}

func TestExplicitRegistration_TrustChainProvided(t *testing.T) {
	// Given.
	ctx, chain := setUpWithChain(t, nil)
	chainStatements := make([]string, len(chain))
	for i, st := range chain {
		chainStatements[i] = st.Signed()
	}

	// When.
	st, err := registerExplicitlyWithChainStatements(ctx, chainStatements)

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

func TestExplicitRegistration_EntityConfigurationProvided(t *testing.T) {
	// Given.
	ctx := setUp(t, nil)
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
			"openid_relying_party": map[string]any{},
		},
		"authority_hints": []string{intermediaryAuthorityID},
	}, clientJWK, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))

	// When.
	st, err := registerExplicitlyWithEntityConfiguration(ctx, entityConfig)

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

func setUpWithChain(t *testing.T, overrideResps map[string]func() *http.Response) (oidc.Context, trustChain) {
	t.Helper()

	ctx := setUp(t, overrideResps)
	_, chain, err := buildAndResolveTrustChain(ctx, clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return ctx, chain
}

func setUp(t *testing.T, overrideResps map[string]func() *http.Response) oidc.Context {
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
					"openid_relying_party": map[string]any{},
				},
				"authority_hints": []string{intermediaryAuthorityID},
				"trust_marks": []any{
					map[string]any{
						"id": trustMarkCertification,
						"trust_mark": oidctest.SignWithOptions(t, map[string]any{
							"trust_mark_id": trustMarkCertification,
							"iss":           trustMarkIssuerID,
							"sub":           clientID,
							"iat":           timeutil.TimestampNow(),
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
					trustMarkCertification: []string{trustMarkIssuerID},
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
	ctx.OpenIDFedEndpoint = "/.well-known/openid-federation"
	ctx.OpenIDFedJWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{opJWK}}, nil
	}
	ctx.OpenIDFedAuthorityHints = []string{trustAnchorID}
	ctx.OpenIDFedTrustedAnchors = []string{trustAnchorID}
	ctx.OpenIDFedEntityStatementSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
	ctx.OpenIDFedTrustChainMaxDepth = 5
	ctx.OpenIDFedClientFunc = Client
	ctx.OpenIDFedTrustMarkSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
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
