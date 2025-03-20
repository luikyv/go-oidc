package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestJARFromRequestObject(t *testing.T) {
	// Given.
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id",
		goidc.KeyUsageSignature)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:         "https://server.example.com",
			JARIsEnabled: true,
			JARSigAlgs: []goidc.SignatureAlgorithm{
				goidc.SignatureAlgorithm(privateJWK.Algorithm),
			},
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			PublicJWKS: oidctest.RawJWKS(privateJWK.Public()),
		},
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
		"scope":             "scope scope2",
		"max_age":           600,
		"acr_values":        "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}
	requestObject := oidctest.Sign(t, claims, privateJWK)

	// When.
	jar, err := jarFromRequestObject(ctx, requestObject, client)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	maxAge := 600
	want := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:     "https://example.com",
			ResponseType:    goidc.ResponseTypeCode,
			Scopes:          "scope scope2",
			MaxAuthnAgeSecs: &maxAge,
			ACRValues:       "0 1",
			Claims: &goidc.ClaimsObject{
				UserInfo: map[string]goidc.ClaimObjectInfo{
					"acr": {Value: "0"},
				},
			},
		},
	}
	if diff := cmp.Diff(jar, want); diff != "" {
		t.Error(diff)
	}
}

func TestJARFromRequestObject_JARByReference(t *testing.T) {
	// Given.
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id",
		goidc.KeyUsageSignature)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:         "https://server.example.com",
			JARIsEnabled: true,
			JARSigAlgs: []goidc.SignatureAlgorithm{
				goidc.SignatureAlgorithm(privateJWK.Algorithm),
			},
			JARByReferenceIsEnabled: true,
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			PublicJWKS: oidctest.RawJWKS(privateJWK.Public()),
		},
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
		"scope":             "scope scope2",
		"max_age":           600,
		"acr_values":        "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}
	requestObject := oidctest.Sign(t, claims, privateJWK)

	// Mock the http request to return a JWKS with a random key.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(requestObject)); err != nil {
			t.Fatal(err)
		}
	}))

	// When.
	jar, err := jarFromRequestURI(ctx, server.URL, client)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	maxAge := 600
	want := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:     "https://example.com",
			ResponseType:    goidc.ResponseTypeCode,
			Scopes:          "scope scope2",
			MaxAuthnAgeSecs: &maxAge,
			ACRValues:       "0 1",
			Claims: &goidc.ClaimsObject{
				UserInfo: map[string]goidc.ClaimObjectInfo{
					"acr": {Value: "0"},
				},
			},
		},
	}
	if diff := cmp.Diff(jar, want); diff != "" {
		t.Error(diff)
	}
}

func TestJARFromRequestObject_Unsigned(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:         "https://server.example.com",
			JARIsEnabled: true,
			JARSigAlgs: []goidc.SignatureAlgorithm{
				goidc.None,
			},
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			JARSigAlg: goidc.None,
		},
	}

	claims := map[string]any{
		"client_id":     client.ID,
		"redirect_uri":  "https://example.com",
		"response_type": goidc.ResponseTypeCode,
		"scope":         "scope scope2",
		"max_age":       600,
		"acr_values":    "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}
	requestObject := joseutil.Unsigned(claims)

	// When.
	jar, err := jarFromRequestObject(ctx, requestObject, client)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	maxAge := 600
	want := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:     "https://example.com",
			ResponseType:    goidc.ResponseTypeCode,
			Scopes:          "scope scope2",
			MaxAuthnAgeSecs: &maxAge,
			ACRValues:       "0 1",
			Claims: &goidc.ClaimsObject{
				UserInfo: map[string]goidc.ClaimObjectInfo{
					"acr": {Value: "0"},
				},
			},
		},
	}
	if diff := cmp.Diff(jar, want); diff != "" {
		t.Error(diff)
	}
}
