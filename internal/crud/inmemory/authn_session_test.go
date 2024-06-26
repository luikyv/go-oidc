package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestCreateOrUpdateAuthnSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	session := goidc.AuthnSession{
		Id: "random_session_id",
	}

	// Then.
	err := manager.CreateOrUpdate(context.Background(), session)

	// Assert.
	if err != nil {
		t.Error("error when upserting the session", err)
	}

	if len(manager.Sessions) != 1 {
		t.Error("there should be exactly one session")
	}

	// Then.
	err = manager.CreateOrUpdate(context.Background(), session)

	// Assert.
	if err != nil {
		t.Error("error when upserting the session", err)
	}

	if len(manager.Sessions) != 1 {
		t.Error("there should be exactly one session")
	}
}

func TestGetAuthnSessionByCallbackId_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	callbackId := "random_callback_id"
	manager.Sessions[sessionId] = goidc.AuthnSession{
		Id:         sessionId,
		CallbackId: callbackId,
	}

	// Then.
	session, err := manager.GetByCallbackId(context.Background(), callbackId)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByAuthorizationCode_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	authorizationCode := "random_authorization_code"
	manager.Sessions[sessionId] = goidc.AuthnSession{
		Id:                sessionId,
		AuthorizationCode: authorizationCode,
	}

	// Then.
	session, err := manager.GetByAuthorizationCode(context.Background(), authorizationCode)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByRequestUri_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	requestUri := "random_request_uri"
	manager.Sessions[sessionId] = goidc.AuthnSession{
		Id: sessionId,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestUri: requestUri,
		},
	}

	// Then.
	session, err := manager.GetByRequestUri(context.Background(), requestUri)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestDeleteAuthnSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	manager.Sessions[sessionId] = goidc.AuthnSession{
		Id: sessionId,
	}

	// Then.
	err := manager.Delete(context.Background(), sessionId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}

	if len(manager.Sessions) != 0 {
		t.Error("there shouldn't be any sessions")
	}
}

func TestDeleteAuthnSession_SessionDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"

	// Then.
	err := manager.Delete(context.Background(), sessionId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}
}
