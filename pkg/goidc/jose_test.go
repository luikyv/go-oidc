package goidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestJSONWebKeySetKey(t *testing.T) {
	// Given.
	jwks := testJWKS(t)

	// When.
	key, err := jwks.Key("test-key")

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.KeyID != "test-key" {
		t.Errorf("KeyID = %s, want test-key", key.KeyID)
	}
}

func TestJSONWebKeySetKey_NotFound(t *testing.T) {
	// Given.
	jwks := testJWKS(t)

	// When.
	_, err := jwks.Key("nonexistent")

	// Then.
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestJSONWebKeySetKeyByAlg(t *testing.T) {
	// Given.
	jwks := testJWKS(t)

	// When.
	key, err := jwks.KeyByAlg("ES256")

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Algorithm != "ES256" {
		t.Errorf("Algorithm = %s, want ES256", key.Algorithm)
	}
}

func TestJSONWebKeySetKeyByAlg_NotFound(t *testing.T) {
	// Given.
	jwks := testJWKS(t)

	// When.
	_, err := jwks.KeyByAlg("RS256")

	// Then.
	if err == nil {
		t.Fatal("expected error for missing algorithm")
	}
}

// TestJSONWebKeySetPublic verifies that Public() returns only public keys
// and strips private key material (RFC 7517 §4).
func TestJSONWebKeySetPublic(t *testing.T) {
	// Given.
	jwks := testJWKS(t)

	// When.
	publicJWKS := jwks.Public()

	// Then.
	if len(publicJWKS.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(publicJWKS.Keys))
	}
	if !publicJWKS.Keys[0].IsPublic() {
		t.Error("key should be public")
	}
}

// TestJSONWebKeySetUnmarshalJSON_SkipsInvalidKeys verifies that invalid keys
// in a JWKS are skipped during deserialization.
func TestJSONWebKeySetUnmarshalJSON_SkipsInvalidKeys(t *testing.T) {
	// Given.
	jwks := testJWKS(t)
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject an invalid key into the raw JSON.
	var raw map[string][]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw["keys"] = append(raw["keys"], json.RawMessage(`{"kty":"invalid"}`))
	modified, _ := json.Marshal(raw) //nolint:errchkjson

	// When.
	var result goidc.JSONWebKeySet
	if err := json.Unmarshal(modified, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Then.
	if len(result.Keys) != 1 {
		t.Errorf("len(Keys) = %d, want 1 (invalid key should be skipped)", len(result.Keys))
	}
}

// TestJSONWebKeySetUnmarshalJSON_NoValidKeys verifies that an error is returned
// when no valid keys are found.
func TestJSONWebKeySetUnmarshalJSON_NoValidKeys(t *testing.T) {
	// Given.
	data := []byte(`{"keys":[{"kty":"invalid"}]}`)

	// When.
	var jwks goidc.JSONWebKeySet
	err := json.Unmarshal(data, &jwks)

	// Then.
	if err == nil {
		t.Fatal("expected error for JWKS with no valid keys")
	}
}

func testJWKS(t *testing.T) goidc.JSONWebKeySet {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}

	return goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{
			{
				Key:       privateKey,
				KeyID:     "test-key",
				Algorithm: "ES256",
				Use:       "sig",
			},
		},
	}
}
