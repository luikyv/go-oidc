package par_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/oauth/par"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestPushAuthorization_ShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	client := utils.GetTestClient(t)
	client.AuthnMethod = goidc.ClientAuthnSecretPost

	ctx := utils.GetTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// Then
	_, err := par.PushAuthorization(ctx, utils.PushedAuthorizationRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     client.ID,
			ClientSecret: "invalid_password",
		},
	})

	// Assert
	require.NotNil(t, err, "the client should not be authenticated")

	var oauthErr goidc.OAuthBaseError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, goidc.ErrorCodeInvalidClient, oauthErr.ErrorCode)
}

func TestPushAuthorization_ShouldGenerateRequestURI(t *testing.T) {
	// When
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)

	client := utils.GetTestClient(t)
	client.AuthnMethod = goidc.ClientAuthnSecretPost
	client.HashedSecret = string(hashedClientSecret)

	ctx := utils.GetTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// Then
	requestURI, err := par.PushAuthorization(ctx, utils.PushedAuthorizationRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: clientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("an error happened: %s", err.Error())
		return
	}
	if requestURI == "" {
		t.Error("the request_uri cannot be empty")
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.RequestURI != requestURI {
		t.Error("the request URI informed is not the same in the session")
		return
	}
}
