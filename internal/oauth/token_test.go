package oauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestHandleGrantCreationShouldNotFindClient(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	// Then
	_, err := oauth.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     "invalid_client_id",
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	})

	// Assert
	if err == nil || !errors.Is(err, issues.ErrorEntityNotFound) {
		t.Error("the should not be found")
		return
	}
}

func TestHandleGrantCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	// Then
	_, err := oauth.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: "invalid_password",
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
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

func TestClientCredentialsHandleGrantCreation(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	}

	// Then
	token, err := oauth.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != oauth.ValidClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != oauth.ValidClientId {
		t.Error("the token subject should be the client")
		return
	}

	grantSessionManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]models.GrantSession, 0, len(grantSessionManager.GrantSessions))
	for _, tk := range grantSessionManager.GrantSessions {
		tokens = append(tokens, tk)
	}
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestHandleGrantCreationWithDpop(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	req := models.TokenRequest{
		DpopJwt: "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ",
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	}

	// Then
	_, err := oauth.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	grantSessionManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	grantSessions := make([]models.GrantSession, 0, len(grantSessionManager.GrantSessions))
	for _, gs := range grantSessionManager.GrantSessions {
		grantSessions = append(grantSessions, gs)
	}
	if len(grantSessions) != 1 {
		t.Error("there should be only one token session")
		return
	}

	if grantSessions[0].JwkThumbprint != "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ" {
		t.Errorf("invalid jwk thumbprint. actual: %s", grantSessions[0].JwkThumbprint)
		return
	}
}

func TestAuthorizationCodeHandleGrantCreation(t *testing.T) {

	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	authorizationCode := "random_authz_code"
	session := models.AuthnSession{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			Scope:       strings.Join(client.Scopes, " "),
			RedirectUri: client.RedirectUris[0],
		},
		AuthorizationCode:     authorizationCode,
		Subject:               "user_id",
		CreatedAtTimestamp:    unit.GetTimestampNow(),
		AuthorizedAtTimestamp: unit.GetTimestampNow(),
		Store:                 make(map[string]string),
		AdditionalTokenClaims: make(map[string]string),
	}
	ctx.AuthnSessionManager.CreateOrUpdate(session)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType:         constants.AuthorizationCodeGrant,
		RedirectUri:       client.RedirectUris[0],
		AuthorizationCode: authorizationCode,
	}

	// Then
	token, err := oauth.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != oauth.ValidClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != session.Subject {
		t.Error("the token subject should be the client")
		return
	}

	tokens := oauth.GetTokenFromMock(ctx)
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestRefreshTokenHandleGrantCreation(t *testing.T) {

	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	token := models.GrantSession{
		Id:                    "random_id",
		GrantModelId:          oauth.ValidGrantModelId,
		Token:                 "token",
		ExpiresInSecs:         60,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: 30,
		CreatedAtTimestamp:    unit.GetTimestampNow(),
		Subject:               username,
		ClientId:              oauth.ValidClientId,
		Scopes:                client.Scopes,
	}
	ctx.GrantSessionManager.CreateOrUpdate(token)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	newToken, err := oauth.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if newToken.ClientId != oauth.ValidClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if newToken.Subject != username {
		t.Error("the token subject should be the client")
		return
	}

	if newToken.RefreshToken == "" || newToken.RefreshToken == refreshToken {
		t.Error("the new refresh token is not valid")
		return
	}

	tokens := oauth.GetTokenFromMock(ctx)
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestRefreshTokenHandleGrantCreationShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	token := models.GrantSession{
		Id:                    "random_id",
		GrantModelId:          oauth.ValidGrantModelId,
		Token:                 "token",
		RefreshToken:          refreshToken,
		ExpiresInSecs:         60,
		RefreshTokenExpiresIn: 0,
		CreatedAtTimestamp:    unit.GetTimestampNow() - 10,
		Subject:               username,
		ClientId:              oauth.ValidClientId,
		Scopes:                client.Scopes,
	}
	ctx.GrantSessionManager.CreateOrUpdate(token)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     oauth.ValidClientId,
			ClientSecretPost: oauth.ValidClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := oauth.HandleGrantCreation(ctx, req)

	// Assert
	if err == nil {
		t.Errorf("the refresh token request should be denied")
		return
	}

}
