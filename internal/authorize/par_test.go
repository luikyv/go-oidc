package authorize_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushAuth(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	// When.
	resp, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  c.RedirectURIS[0],
			Scopes:       c.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, resp.RequestURI)

	sessions := oidc.TestAuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, resp.RequestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuth_WithJAR(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	ctx.JAR.IsEnabled = true
	ctx.JAR.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JAR.LifetimeSecs = 60

	privateJWK := oidc.TestPrivateRS256JWK(t, "rsa256_key")
	c, _ := ctx.Client(oidc.TestClientID)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJWK.Public()}})
	c.PublicJWKS = jwks
	require.Nil(t, ctx.SaveClient(c))

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + 10,
		"client_id":         c.ID,
		"redirect_uri":      c.RedirectURIS[0],
		"scope":             c.Scopes,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// When.
	resp, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, resp.RequestURI)

	sessions := oidc.TestAuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, resp.RequestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuth_ShouldRejectUnauthenticatedClient(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	// When.
	_, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     c.ID,
			Secret: "invalid_password",
		},
	})

	// Then.
	require.NotNil(t, err, "the client should not be authenticated")

	var oauthErr oidc.Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oidc.ErrorCodeInvalidClient, oauthErr.Code())
}
