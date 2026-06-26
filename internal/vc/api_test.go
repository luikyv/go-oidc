package vc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRegisterHandlers_OffersDisabled(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		VCISelfEnabled:            true,
		VCISelfCredentialEndpoint: "/credential",
		VCISelfOfferEndpoint:      "/credential_offer",
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/credential_offer/id", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestRegisterHandlers_JWTIssuerMetadataDisabled(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		VCISelfEnabled:            true,
		VCISelfCredentialEndpoint: "/credential",
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwt-vc-issuer", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestHandleJWTIssuerMetadata_URI(t *testing.T) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		Host:                         "https://op.example.com",
		VCISelfEnabled:               true,
		VCISelfHost:                  "https://credential-issuer.example.com",
		VCISelfCredentialEndpoint:    "/credential",
		VCISelfJWTIssuerEnabled:      true,
		VCISelfJWTIssuerJWKSURI:      "https://credential-issuer.example.com/jwks",
		VCISelfJWTIssuerJWKSFunc:     nil,
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwt-vc-issuer", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var got jwtIssuerMetadata
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Issuer != "https://credential-issuer.example.com" {
		t.Fatalf("issuer = %q, want %q", got.Issuer, "https://credential-issuer.example.com")
	}
	if got.JWKSURI != "https://credential-issuer.example.com/jwks" {
		t.Fatalf("jwks_uri = %q, want %q", got.JWKSURI, "https://credential-issuer.example.com/jwks")
	}
	if got.JWKS != nil {
		t.Fatal("jwks must be empty when jwks_uri is set")
	}
}

func TestHandleJWTIssuerMetadata_InlineJWKS(t *testing.T) {
	jwk := oidctest.PrivateRS256JWK(t, "jwt_vc_issuer_key", goidc.KeyUsageSignature)
	mux := http.NewServeMux()
	RegisterHandlers(mux, &oidc.Configuration{
		Host:                      "https://op.example.com",
		VCISelfEnabled:            true,
		VCISelfHost:               "https://credential-issuer.example.com",
		VCISelfCredentialEndpoint: "/credential",
		VCISelfJWTIssuerEnabled:   true,
		VCISelfJWTIssuerJWKSFunc: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwt-vc-issuer", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var got jwtIssuerMetadata
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.JWKSURI != "" {
		t.Fatalf("jwks_uri = %q, want empty", got.JWKSURI)
	}
	if got.JWKS == nil {
		t.Fatal("jwks must be set")
	}
	if len(got.JWKS.Keys) != 1 {
		t.Fatalf("jwks keys count = %d, want 1", len(got.JWKS.Keys))
	}
	if got.JWKS.Keys[0].KeyID != "jwt_vc_issuer_key" {
		t.Fatalf("jwk kid = %q, want %q", got.JWKS.Keys[0].KeyID, "jwt_vc_issuer_key")
	}
	if _, ok := got.JWKS.Keys[0].Key.(*rsa.PublicKey); !ok {
		t.Fatalf("jwk key type = %T, want *rsa.PublicKey", got.JWKS.Keys[0].Key)
	}
}
