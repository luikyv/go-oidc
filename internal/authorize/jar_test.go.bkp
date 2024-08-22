package authorize_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractJARFromRequestObject_SignedRequestObjectHappyPath(t *testing.T) {
	// Given.
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id")
	config := oidc.Configuration{
		Host: "https://server.example.com",
	}
	config.JAR.IsEnabled = true
	config.JAR.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJWK.Algorithm)}
	config.JAR.LifetimeSecs = 60
	ctx := &oidc.Context{
		Configuration: config,
		Req: &http.Request{
			Method: http.MethodPost,
		},
	}

	client := &goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKS: oidctest.RawJWKS(privateJWK.Public()),
		},
	}

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.JAR.LifetimeSecs - 1,
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
	request, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// When.
	jar, err := authorize.JARFromRequestObject(ctx, request, client)

	// Then.
	require.Nil(t, err, "error extracting JAR")
	assert.Equal(t, client.ID, jar.ClientID, "invalid JAR client_id")
	assert.Equal(t, goidc.ResponseTypeCode, jar.ResponseType, "invalid JAR response_type")
}
