package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestClient(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*testing.T) (oidc.Context, string)
		wantClientID string
		wantErr      error
	}{
		{
			name: "static client",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				staticClient := &goidc.Client{ID: "static_client"}
				ctx.StaticClients = append(ctx.StaticClients, staticClient)
				return ctx, staticClient.ID
			},
			wantClientID: "static_client",
		},
		{
			name: "static client takes precedence over federation and dcr",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				fedManager := storage.NewManager(100)
				dcrManager := storage.NewManager(100)
				clientID := "https://client.example.com"
				staticClient := &goidc.Client{ID: clientID}
				fedClient := &goidc.Client{ID: clientID}
				dcrClient := &goidc.Client{ID: clientID}
				ctx.StaticClients = append(ctx.StaticClients, staticClient)
				ctx.OpenIDFedEnabled = true
				ctx.OpenIDFedManager = fedManager
				ctx.DCREnabled = true
				ctx.DCRManager = dcrManager
				if err := ctx.OpenIDFedSaveClient(fedClient); err != nil {
					t.Fatalf("could not save federation client: %v", err)
				}
				if err := ctx.DCRSaveClient(dcrClient); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, clientID
			},
			wantClientID: "https://client.example.com",
		},
		{
			name: "federation client",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				manager := oidctest.Manager(t, ctx)
				fedClient := &goidc.Client{ID: "https://client.example.com"}
				ctx.OpenIDFedEnabled = true
				ctx.OpenIDFedManager = manager
				if err := ctx.OpenIDFedSaveClient(fedClient); err != nil {
					t.Fatalf("could not save federation client: %v", err)
				}
				return ctx, fedClient.ID
			},
			wantClientID: "https://client.example.com",
		},
		{
			name: "federation url does not fall back to dcr",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				ctx.OpenIDFedManager = storage.NewManager(100)
				ctx.DCRManager = storage.NewManager(100)
				clientID := "https://client.example.com"
				ctx.OpenIDFedEnabled = true
				ctx.DCREnabled = true
				if err := ctx.DCRSaveClient(&goidc.Client{ID: clientID}); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, clientID
			},
			wantErr: goidc.ErrNotFound,
		},
		{
			name: "dcr client",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				manager := oidctest.Manager(t, ctx)
				dcrClient := &goidc.Client{ID: "dcr_client"}
				ctx.DCREnabled = true
				ctx.DCRManager = manager
				if err := ctx.DCRSaveClient(dcrClient); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, dcrClient.ID
			},
			wantClientID: "dcr_client",
		},
		{
			name: "non url skips federation and uses dcr",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx := oidctest.NewContext(t)
				manager := oidctest.Manager(t, ctx)
				dcrClient := &goidc.Client{ID: "dcr_client"}
				ctx.OpenIDFedEnabled = true
				ctx.OpenIDFedManager = manager
				ctx.DCREnabled = true
				ctx.DCRManager = manager
				if err := ctx.DCRSaveClient(dcrClient); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, dcrClient.ID
			},
			wantClientID: "dcr_client",
		},
		{
			name: "not found",
			setup: func(t *testing.T) (oidc.Context, string) {
				return oidctest.NewContext(t), "missing_client"
			},
			wantErr: goidc.ErrNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, id := test.setup(t)

			got, err := Client(ctx, id)

			if test.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v", test.wantErr)
				}
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected client")
			}
			if got.ID != test.wantClientID {
				t.Fatalf("client ID = %q, want %q", got.ID, test.wantClientID)
			}
		})
	}
}

func TestFetchPublicJWKS(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)
	numberOfCalls := 0
	// Mock the http request to return a JWKS with a random key.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numberOfCalls++
		jwk := oidctest.PrivatePS256JWK(t, "random_key_id", goidc.KeyUsageSignature)
		if err := json.NewEncoder(w).Encode(goidc.JSONWebKeySet{
			Keys: []goidc.JSONWebKey{jwk},
		}); err != nil {
			t.Fatal(err)
		}
	}))

	c := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			JWKSURI: server.URL,
			JWKS:    nil,
		},
	}

	for i := range 2 {
		// When.
		_, err := JWKS(ctx, c)
		// Then.
		if err != nil {
			t.Fatalf("unexpected error during attempt %d: %v", i+1, err)
		}

		if numberOfCalls != 1 {
			t.Errorf("number of requests = %d, want 1. attempt %d", numberOfCalls, i+1)
		}

		if c.CachedJWKS() == nil {
			t.Errorf("the jwks was not cached. attempt %d", i+1)
		}
	}
}

func TestJWKByAlg(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T) (oidc.Context, *goidc.Client, string)
		wantKeyID   string
		wantErrText string
	}{
		{
			name: "success",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx := oidctest.NewContext(t)
				psJWK := oidctest.PrivatePS256JWK(t, "ps256_key", goidc.KeyUsageSignature)
				rsJWK := oidctest.PrivateRS256JWK(t, "rs256_key", goidc.KeyUsageSignature)
				c := &goidc.Client{
					ClientMeta: goidc.ClientMeta{
						JWKS: &goidc.JSONWebKeySet{
							Keys: []goidc.JSONWebKey{psJWK.Public(), rsJWK.Public()},
						},
					},
				}
				return ctx, c, string(goidc.RS256)
			},
			wantKeyID: "rs256_key",
		},
		{
			name: "jwks load failure",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx := oidctest.NewContext(t)
				c := &goidc.Client{}
				return ctx, c, string(goidc.RS256)
			},
			wantErrText: "could not find the jwk by algorithm: the client jwks was informed neither by value nor by reference",
		},
		{
			name: "algorithm not found",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx := oidctest.NewContext(t)
				psJWK := oidctest.PrivatePS256JWK(t, "ps256_key", goidc.KeyUsageSignature)
				c := &goidc.Client{
					ClientMeta: goidc.ClientMeta{
						JWKS: &goidc.JSONWebKeySet{
							Keys: []goidc.JSONWebKey{psJWK.Public()},
						},
					},
				}
				return ctx, c, string(goidc.RS256)
			},
			wantErrText: "invalid key algorithm: RS256",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, client, alg := test.setup(t)

			got, err := JWKByAlg(ctx, client, alg)

			if test.wantErrText != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErrText)
				}
				if !strings.Contains(err.Error(), test.wantErrText) {
					t.Fatalf("error = %q, want to contain %q", err.Error(), test.wantErrText)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.KeyID != test.wantKeyID {
				t.Fatalf("key ID = %q, want %q", got.KeyID, test.wantKeyID)
			}
		})
	}
}
