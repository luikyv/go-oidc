package par_test

import (
	"errors"
	"testing"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth/par"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestPushAuthorization_ShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	client := models.GetTestClient()
	client.AuthnMethod = goidc.ClientSecretPostAuthn

	ctx := utils.GetTestInMemoryContext()
	ctx.CreateClient(client)

	// Then
	_, err := par.PushAuthorization(ctx, models.PushedAuthorizationRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     client.Id,
			ClientSecret: "invalid_password",
		},
	})

	// Assert
	var jsonError goidc.OAuthBaseError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the client should not be authenticated")
		return
	}
	if jsonError.ErrorCode != goidc.InvalidClient {
		t.Errorf("invalid error code: %s", jsonError.ErrorCode)
		return
	}
}

func TestPushAuthorization_ShouldGenerateRequestUri(t *testing.T) {
	// When
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)

	client := models.GetTestClient()
	client.AuthnMethod = goidc.ClientSecretPostAuthn
	client.HashedSecret = string(hashedClientSecret)

	ctx := utils.GetTestInMemoryContext()
	ctx.CreateClient(client)

	// Then
	requestUri, err := par.PushAuthorization(ctx, models.PushedAuthorizationRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     models.TestClientId,
			ClientSecret: clientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.CodeResponse,
			ResponseMode: goidc.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("an error happened: %s", err.Error())
		return
	}
	if requestUri == "" {
		t.Error("the request_uri cannot be empty")
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.RequestUri != requestUri {
		t.Error("the request URI informed is not the same in the session")
		return
	}
}
