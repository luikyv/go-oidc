package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSaveLogoutSession(t *testing.T) {
	// Given.
	manager := storage.NewLogoutSessionManager(1)
	session := &goidc.LogoutSession{
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

func TestLogoutSessionByCallbackID(t *testing.T) {
	// Given.
	manager := storage.NewLogoutSessionManager(1)
	sessionID := "random_session_id"
	callbackID := "random_callback_id"
	manager.Sessions[sessionID] = &goidc.LogoutSession{
		ID:         sessionID,
		CallbackID: callbackID,
	}

	// When.
	session, err := manager.SessionByCallbackID(context.Background(), callbackID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestDeleteLogoutSession(t *testing.T) {
	// Given.
	manager := storage.NewLogoutSessionManager(1)
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.LogoutSession{
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

func TestDeleteLogoutSession_SessionDoesNotExist(t *testing.T) {
	// Given.
	manager := storage.NewLogoutSessionManager(1)
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
