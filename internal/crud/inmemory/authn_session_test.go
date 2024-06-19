package inmemory_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
)

func TestCreateOrUpdateAuthnSession_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	session := models.AuthnSession{
		Id: "random_session_id",
	}

	// Then.
	err := manager.CreateOrUpdate(session)

	// Assert.
	if err != nil {
		t.Error("error when upserting the session", err)
	}

	if len(manager.Sessions) != 1 {
		t.Error("there should be exactly one session")
	}

	// Then.
	err = manager.CreateOrUpdate(session)

	// Assert.
	if err != nil {
		t.Error("error when upserting the session", err)
	}

	if len(manager.Sessions) != 1 {
		t.Error("there should be exactly one session")
	}
}

func TestGetAuthnSessionByCallbackId_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	callbackId := "random_callback_id"
	manager.Sessions[sessionId] = models.AuthnSession{
		Id:         sessionId,
		CallbackId: callbackId,
	}

	// Then.
	session, err := manager.GetByCallbackId(callbackId)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByAuthorizationCode_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	authorizationCode := "random_authorization_code"
	manager.Sessions[sessionId] = models.AuthnSession{
		Id:                sessionId,
		AuthorizationCode: authorizationCode,
	}

	// Then.
	session, err := manager.GetByAuthorizationCode(authorizationCode)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByRequestUri_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	requestUri := "random_request_uri"
	manager.Sessions[sessionId] = models.AuthnSession{
		Id: sessionId,
		AuthorizationParameters: models.AuthorizationParameters{
			RequestUri: requestUri,
		},
	}

	// Then.
	session, err := manager.GetByRequestUri(requestUri)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestDeleteAuthnSession_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"
	manager.Sessions[sessionId] = models.AuthnSession{
		Id: sessionId,
	}

	// Then.
	err := manager.Delete(sessionId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}

	if len(manager.Sessions) != 0 {
		t.Error("there shouldn't be any sessions")
	}
}

func TestDeleteAuthnSession_SessionDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryAuthnSessionManager()
	sessionId := "random_session_id"

	// Then.
	err := manager.Delete(sessionId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}
}
