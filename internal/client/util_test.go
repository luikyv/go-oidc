package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestAreScopesAllowed(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Scopes = []goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
		goidc.NewScope("scope3"),
	}

	c := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			ScopeIDs: "scope1 scope2 scope3",
		},
	}

	testCases := []struct {
		requestedScopes string
		want            bool
	}{
		{"scope1 scope3", true},
		{"scope3 scope2", true},
		{"invalid_scope scope3", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				got := AreScopesAllowed(ctx, c, testCase.requestedScopes)
				if got != testCase.want {
					t.Errorf("AreScopesAllowed() = %t, want %t", got, testCase.want)
				}
			},
		)
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

		if c.JWKS.Keys == nil {
			t.Errorf("the jwks was not cached. attempt %d", i+1)
		}
	}
}
