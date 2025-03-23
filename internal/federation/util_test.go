package federation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
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
	clientID               string = "https://client.testfed.com"
	trustAnchorID          string = "https://trust-anchor.testfed.com"
	trustMarkIssuerID      string = "https://trust-mark-issuer.testfed.com"
	trustMarkCertification string = trustMarkIssuerID + "/certification"
)

var (
	clientKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	clientJWK    = goidc.JSONWebKey{
		KeyID:     "client_key",
		Key:       clientKey,
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
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context) []string {
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
						}, clientJWK, (&jose.SignerOptions{}).WithType(trustMarkJWTType)),
					},
				},
			}, clientJWK, (&jose.SignerOptions{}).WithType(entityStatementJWTType))
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setUp(t, responses)
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context) []string {
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
						}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(trustMarkJWTType)),
					},
				},
			}, clientJWK, (&jose.SignerOptions{}).WithType(entityStatementJWTType))
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}
	ctx := setUp(t, responses)
	ctx.OpenIDFedRequiredTrustMarksFunc = func(ctx context.Context) []string {
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
		trustAnchorID + "/fetch?sub=" + url.QueryEscape(clientID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
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
			}, trustAnchorJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{entityStatementJWTContentType},
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
				"authority_hints": []string{trustAnchorID},
				"trust_marks": []any{
					map[string]any{
						"id": trustMarkCertification,
						"trust_mark": oidctest.SignWithOptions(t, map[string]any{
							"trust_mark_id": trustMarkCertification,
							"iss":           trustMarkIssuerID,
							"sub":           clientID,
							"iat":           timeutil.TimestampNow(),
						}, trustMarkIssuerJWK, (&jose.SignerOptions{}).WithType(trustMarkJWTType)),
					},
				},
			}, clientJWK, (&jose.SignerOptions{}).WithType(entityStatementJWTType))
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/.well-known/openid-federation": func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
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
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustMarkIssuerID + "/.well-known/openid-federation": func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
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
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/fetch?sub=" + url.QueryEscape(clientID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
			st := oidctest.SignWithOptions(t, map[string]any{
				"iss": trustAnchorID,
				"sub": clientID,
				"iat": timeutil.TimestampNow(),
				"exp": timeutil.TimestampNow() + 600,
				"jwks": jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{clientJWK.Public()},
				},
			}, trustAnchorJWK, opts)
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},

		trustAnchorID + "/fetch?sub=" + url.QueryEscape(trustMarkIssuerID): func() *http.Response {
			opts := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
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
					"Content-Type": []string{entityStatementJWTContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(st)),
			}
		},
	}

	for key, value := range overrideResps {
		responses[key] = value
	}

	ctx := oidctest.NewContext(t)
	ctx.OpenIDFedIsEnabled = true
	ctx.OpenIDFedEndpoint = "/.well-known/openid-federation"
	ctx.OpenIDFedJWKSFunc = nil
	ctx.OpenIDFedAuthorityHints = []string{trustAnchorID}
	ctx.OpenIDFedTrustedAuthorities = []string{trustAnchorID}
	ctx.OpenIDFedEntityStatementSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
	ctx.OpenIDFedTrustChainMaxDepth = 5
	ctx.OpenIDFedClientFunc = Client
	ctx.OpenIDFedTrustMarkSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
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
