package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSaveAuthnSession(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	session := &goidc.AuthnSession{
		ID: "random_session_id",
	}

	for i := 0; i < 2; i++ {
		// When.
		err := manager.Save(context.Background(), session)

		// Then.
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(manager.Sessions) != 1 {
			t.Errorf("len(manager.Sessions) = %d, want 1", len(manager.Sessions))
		}
	}
}

func TestAuthnSessionByCallbackID(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	sessionID := "random_session_id"
	callbackID := "random_callback_id"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID:         sessionID,
		CallbackID: callbackID,
	}

	// When.
	session, err := manager.GetByCallbackID(context.Background(), callbackID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestAuthnSessionByAuthorizationCode(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	sessionID := "random_session_id"
	authorizationCode := "random_authorization_code"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID:                sessionID,
		AuthorizationCode: authorizationCode,
	}

	// When.
	session, err := manager.GetByAuthorizationCode(context.Background(), authorizationCode)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestAuthnSessionByRequestURI(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	sessionID := "random_session_id"
	requestURI := "random_request_uri"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID: sessionID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI: requestURI,
		},
	}

	// When.
	session, err := manager.GetByRequestURI(context.Background(), requestURI)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestDeleteAuthnSession(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID: sessionID,
	}

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.Sessions) != 0 {
		t.Errorf("len(manager.Sessions) = %d, want 0", len(manager.Sessions))
	}
}

func TestDeleteAuthnSession_SessionDoesNotExist(t *testing.T) {
	// Given.
	manager := storage.NewAuthnSessionManager()
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
