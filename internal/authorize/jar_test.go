package authorize

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestExtractJARFromRequestObject(t *testing.T) {
	// Given.
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id",
		goidc.KeyUsageSignature)
	ctx := &oidc.Context{
		Configuration: oidc.Configuration{
			Host:         "https://server.example.com",
			JARIsEnabled: true,
			JARSigAlgs: []jose.SignatureAlgorithm{
				jose.SignatureAlgorithm(privateJWK.Algorithm),
			},
			JARLifetimeSecs: 60,
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKS: oidctest.RawJWKS(privateJWK.Public()),
		},
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.JARLifetimeSecs - 10,
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
	requestObject, _ := jwtutil.Sign(
		claims,
		privateJWK,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)

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
