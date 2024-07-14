package par_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/oauth/par"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushAuthorization(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	// When.
	requestURI, err := par.PushAuthorization(ctx, utils.PushedAuthorizationRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, requestURI)

	sessions := utils.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, requestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuthorization_WithJAR(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	ctx.JARIsEnabled = true
	ctx.JARSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JARLifetimeSecs = 60

	privateJWK := utils.PrivateRS256JWK(t, "rsa256_key")
	client, _ := ctx.Client(utils.TestClientID)
	client.PublicJWKS = &goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{privateJWK.Public()},
	}
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	createdAtTimestamp := goidc.TimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm()), Key: privateJWK.Key()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID()),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + 10,
		"client_id":         client.ID,
		"redirect_uri":      client.RedirectURIS[0],
		"scope":             client.Scopes,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// When.
	requestURI, err := par.PushAuthorization(ctx, utils.PushedAuthorizationRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, requestURI)

	sessions := utils.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, requestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuthorization_ShouldRejectUnauthenticatedClient(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	// When.
	_, err := par.PushAuthorization(ctx, utils.PushedAuthorizationRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     client.ID,
			ClientSecret: "invalid_password",
		},
	})

	// Then.
	require.NotNil(t, err, "the client should not be authenticated")

	var oauthErr goidc.OAuthBaseError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, goidc.ErrorCodeInvalidClient, oauthErr.ErrorCode)
}
