package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestCreateOrUpdateAuthnSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewAuthnSessionManager()
	session := goidc.AuthnSession{
		ID: "random_session_id",
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

func TestGetAuthnSessionByCallbackID_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	callbackID := "random_callback_id"
	manager.Sessions[sessionID] = goidc.AuthnSession{
		ID:         sessionID,
		CallbackID: callbackID,
	}

	// Then.
	session, err := manager.GetByCallbackID(context.Background(), callbackID)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.ID != sessionID {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByAuthorizationCode_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	authorizationCode := "random_authorization_code"
	manager.Sessions[sessionID] = goidc.AuthnSession{
		ID:                sessionID,
		AuthorizationCode: authorizationCode,
	}

	// Then.
	session, err := manager.GetByAuthorizationCode(context.Background(), authorizationCode)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.ID != sessionID {
		t.Error("invalid session ID")
	}
}

func TestGetAuthnSessionByRequestURI_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	requestURI := "random_request_uri"
	manager.Sessions[sessionID] = goidc.AuthnSession{
		ID: sessionID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI: requestURI,
		},
	}

	// Then.
	session, err := manager.GetByRequestURI(context.Background(), requestURI)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.ID != sessionID {
		t.Error("invalid session ID")
	}
}

func TestDeleteAuthnSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = goidc.AuthnSession{
		ID: sessionID,
	}

	// Then.
	err := manager.Delete(context.Background(), sessionID)

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
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"

	// Then.
	err := manager.Delete(context.Background(), sessionID)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}
}
