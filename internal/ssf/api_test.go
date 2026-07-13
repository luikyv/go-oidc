package ssf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRegisterHandlers(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(testing.TB) oidc.Context
		method     string
		path       string
		body       string
		mediaType  string
		wantStatus int
		validate   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "configuration endpoint includes issuer path",
			setup: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFEnabled = true
				ctx.SSFIssuer = "https://example.com/issuer"
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				return ctx
			},
			method:     http.MethodGet,
			path:       "/.well-known/ssf-configuration/issuer",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				var resp configuration
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("could not decode response: %v", err)
				}
				if resp.ConfigurationEndpoint != "https://example.com/issuer/ssf/configuration" {
					t.Fatalf("configuration endpoint = %q, want https://example.com/issuer/ssf/configuration", resp.ConfigurationEndpoint)
				}
			},
		},
		{
			name: "jwks endpoint includes endpoint prefix",
			setup: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFEnabled = true
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFJWKSFunc = ctx.JWKSFunc
				return ctx
			},
			method:     http.MethodGet,
			path:       "/ssf/jwks",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				var jwks goidc.JSONWebKeySet
				if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
					t.Fatalf("could not decode JWKS: %v", err)
				}
				if len(jwks.Keys) == 0 {
					t.Fatal("jwks keys should not be empty")
				}
				if !jwks.Keys[0].IsPublic() {
					t.Fatal("jwks endpoint should not expose private key material")
				}
			},
		},
		{
			name: "create stream rejects unsupported content type",
			setup: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFEnabled = true
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFConfigurationEndpoint = "/configuration"
				return ctx
			},
			method:     http.MethodPost,
			path:       "/ssf/configuration",
			body:       "{}",
			mediaType:  "text/plain",
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name: "create stream rejects invalid json",
			setup: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFEnabled = true
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFConfigurationEndpoint = "/configuration"
				return ctx
			},
			method:     http.MethodPost,
			path:       "/ssf/configuration",
			body:       "{",
			mediaType:  "application/json",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "poll endpoint uses stream id path value",
			setup: func(tb testing.TB) oidc.Context {
				manager := storage.NewManager(100)
				ctx := oidctest.NewContext(tb)
				ctx.SSFEnabled = true
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFPollingEndpoint = "/poll"
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				ctx.SSFStreamManager = manager
				ctx.SSFEventPollManager = manager
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{ID: "receiver_id"}, nil
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx
			},
			method:     http.MethodPost,
			path:       "/ssf/poll/stream_id",
			body:       "{}",
			mediaType:  "application/json",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				var resp responsePollEvents
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("could not decode poll response: %v", err)
				}
				if len(resp.SecurityEventTokens) != 0 {
					t.Fatalf("sets = %d, want 0", len(resp.SecurityEventTokens))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx := tt.setup(t)
			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.mediaType != "" {
				req.Header.Set("Content-Type", tt.mediaType)
			}
			rec := httptest.NewRecorder()

			// When.
			mux.ServeHTTP(rec, req)

			// Then.
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.validate != nil {
				tt.validate(t, rec)
			}
		})
	}
}
