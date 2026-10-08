package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenEndpointErrorStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*goidc.Client, url.Values)
		wantCode   goidc.ErrorCode
		wantStatus int
	}{
		{
			name: "invalid client authentication uses 401",
			setup: func(_ *goidc.Client, form url.Values) {
				form.Set("client_secret", "invalid_secret")
			},
			wantCode:   goidc.ErrorCodeInvalidClient,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unauthorized client uses 400",
			setup: func(client *goidc.Client, _ url.Values) {
				client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
			},
			wantCode:   goidc.ErrorCodeUnauthorizedClient,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
				"scope":         {"scope1"},
			}
			test.setup(client, form)

			req := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			handleCreate(oidc.NewHTTPContext(rec, req, ctx.Configuration))

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, test.wantStatus)
			}
			var body struct {
				Error goidc.ErrorCode `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Error != test.wantCode {
				t.Fatalf("error = %s, want %s", body.Error, test.wantCode)
			}
		})
	}
}
