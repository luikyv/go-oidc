package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
)

func TestRegisterHandlers_AuthorizationServerMetadata(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		paths  []string
	}{
		{
			name:   "issuer without path",
			issuer: "https://example.com",
			paths: []string{
				"/.well-known/oauth-authorization-server",
				"/.well-known/openid-configuration",
			},
		},
		{
			name:   "issuer with path",
			issuer: "https://example.com/tenant/issuer",
			paths: []string{
				"/.well-known/oauth-authorization-server/tenant/issuer",
				"/tenant/issuer/.well-known/openid-configuration",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.Host = test.issuer
			ctx.DCREnabled = false
			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			for _, path := range test.paths {
				recorder := httptest.NewRecorder()
				mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

				if recorder.Code != http.StatusOK {
					t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
				}
				var metadata map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
					t.Fatalf("decode metadata from %s: %v", path, err)
				}
				if metadata["issuer"] != test.issuer {
					t.Fatalf("GET %s issuer = %v, want %q", path, metadata["issuer"], test.issuer)
				}
				if _, advertised := metadata["registration_endpoint"]; advertised {
					t.Fatalf("GET %s advertises registration_endpoint while DCR is disabled", path)
				}
			}
		})
	}
}

func TestRegisterHandlersRejectsNonStandardPathBasedOIDCMetadataRoute(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.Host = "https://example.com/tenant/issuer"
	mux := http.NewServeMux()
	RegisterHandlers(mux, ctx.Configuration)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration/tenant/issuer", nil),
	)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("non-standard OIDC metadata route status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
