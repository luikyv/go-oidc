package oauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestPushAuthorizationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()

	// Then
	_, err := oauth.PushAuthorization(ctx, models.PushedAuthorizationRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: "invalid_password",
		},
	})

	// Assert
	var jsonError issues.OAuthBaseError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the client should not be authenticated")
		return
	}
	if jsonError.ErrorCode != constants.InvalidClient {
		t.Errorf("invalid error code: %s", jsonError.ErrorCode)
		return
	}
}

func TestPushAuthorizationShouldGenerateRequestUri(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	// Then
	requestUri, err := oauth.PushAuthorization(ctx, models.PushedAuthorizationRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeResponse,
			ResponseMode: constants.QueryResponseMode,
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

	sessions := oauth.GetSessionsFromMock(ctx)
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
