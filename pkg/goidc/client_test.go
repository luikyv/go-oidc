package goidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestFetchPublicJWKS(t *testing.T) {

	// Given.
	numberOfCalls := 0
	// Mock the http request to return a JWKS with a random key.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numberOfCalls++
		jwk := privatePs256JWK("random_key_id")
		if err := json.NewEncoder(w).Encode(goidc.JSONWebKeySet{
			Keys: []goidc.JSONWebKey{jwk},
		}); err != nil {
			t.Fatal(err)
		}
	}))

	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKSURI: server.URL,
			PublicJWKS:    nil,
		},
	}

	for i := 0; i < 2; i++ {
		// When.
		_, err := client.FetchPublicJWKS(http.DefaultClient)
		// Then.
		if err != nil {
			t.Fatalf("unexpected error during attempt %d: %v", i+1, err)
		}

		if numberOfCalls != 1 {
			t.Errorf("number of requests = %d, want 1. attempt %d", numberOfCalls, i+1)
		}

		if client.PublicJWKS == nil {
			t.Errorf("the jwks was not cached. attempt %d", i+1)
		}
	}
}

func privatePs256JWK(keyID string) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(goidc.PS256),
		Use:       string(goidc.KeyUsageSignature),
	}
}
