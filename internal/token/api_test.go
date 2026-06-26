package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRegisterHandlers(t *testing.T) {
	tests := []struct {
		name             string
		enableIntrospect bool
		enableRevoke     bool
		validate         func(*testing.T, *http.ServeMux, oidc.Context)
	}{
		{
			name: "registers token endpoint",
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				ctx.StaticClients = append(ctx.StaticClients, client)

				form := url.Values{
					"grant_type":    {string(goidc.GrantClientCredentials)},
					"client_id":     {client.ID},
					"client_secret": {secret},
					"scope":         {"scope1"},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
			},
		},
		{
			name:             "registers introspection endpoint when enabled",
			enableIntrospect: true,
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				client.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return true
				}

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{ID: "grant_id", ClientID: client.ID, CreatedAt: now}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				jwks := oidctest.PrivateJWKS(t, ctx)
				tknValue := oidctest.Sign(t, map[string]any{
					"jti":       "token_id",
					"grant_id":  grant.ID,
					"iss":       ctx.Issuer(),
					"client_id": client.ID,
					"iat":       now,
					"exp":       now + 60,
				}, jwks.Keys[0])

				form := url.Values{
					"token":           {tknValue},
					"token_type_hint": {string(goidc.TokenHintAccess)},
					"client_id":       {client.ID},
					"client_secret":   {secret},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenIntrospectionEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
				if !strings.Contains(rec.Body.String(), `"active":true`) {
					t.Fatalf("response = %s, want active token", rec.Body.String())
				}
			},
		},
		{
			name:         "registers revocation endpoint when enabled",
			enableRevoke: true,
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				client.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretPost
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return true
				}
				ctx.RefreshTokenManager = oidctest.Manager(t, ctx)

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:           "grant_id",
					ClientID:     client.ID,
					RefreshToken: "refresh_token",
					CreatedAt:    now,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				form := url.Values{
					"token":           {grant.RefreshToken},
					"token_type_hint": {string(goidc.TokenHintRefresh)},
					"client_id":       {client.ID},
					"client_secret":   {secret},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenRevocationEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.TokenIntrospectionEnabled = test.enableIntrospect
			ctx.TokenRevocationEnabled = test.enableRevoke
			if ctx.TokenIntrospectionEndpoint == "" {
				ctx.TokenIntrospectionEndpoint = "/introspect"
			}
			if ctx.TokenRevocationEndpoint == "" {
				ctx.TokenRevocationEndpoint = "/revoke"
			}

			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			test.validate(t, mux, ctx)
		})
	}
}

func TestTokenHandlersInvalidContentType(t *testing.T) {
	tests := []struct {
		name string
		path string
		fn   func(oidc.Context)
	}{
		{name: "create", path: "/token", fn: handleCreate},
		{name: "introspection", path: "/introspect", fn: handleIntrospection},
		{name: "revocation", path: "/revoke", fn: handleRevocation},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader("x"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			httpCtx := oidc.NewHTTPContext(rec, req, ctx.Configuration)
			test.fn(httpCtx)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if !strings.Contains(rec.Body.String(), string(goidc.ErrorCodeInvalidRequest)) {
				t.Fatalf("response = %s, want invalid_request", rec.Body.String())
			}
		})
	}
}
