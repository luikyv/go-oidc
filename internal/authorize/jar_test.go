package authorize

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractJARFromRequestObject_SignedRequestObjectHappyPath(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "client_key_id")
	ctx := &oidc.Context{
		Configuration: oidc.Configuration{
			Host:                   "https://server.example.com",
			JARIsEnabled:           true,
			JARSignatureAlgorithms: []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJWK.Algorithm)},
			JARLifetimeSecs:        60,
		},
		Req: &http.Request{
			Method: http.MethodPost,
		},
	}

	client := &goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKS: oidc.RawJWKS(privateJWK.Public()),
		},
	}

	createdAtTimestamp := goidc.TimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		string(goidc.ClaimIssuer):   client.ID,
		string(goidc.ClaimAudience): ctx.Host,
		string(goidc.ClaimIssuedAt): createdAtTimestamp,
		string(goidc.ClaimExpiry):   createdAtTimestamp + ctx.JARLifetimeSecs - 1,
		"client_id":                 client.ID,
		"redirect_uri":              "https://example.com",
		"response_type":             goidc.ResponseTypeCode,
		"scope":                     "scope scope2",
		"max_age":                   600,
		"acr_values":                "0 1",
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
	jar, err := JARFromRequestObject(ctx, request, client)

	// Then.
	require.Nil(t, err, "error extracting JAR")
	assert.Equal(t, client.ID, jar.ClientID, "invalid JAR client_id")
	assert.Equal(t, goidc.ResponseTypeCode, jar.ResponseType, "invalid JAR response_type")
}
