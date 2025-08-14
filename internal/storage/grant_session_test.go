package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSaveGrantSession(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager(1)
	session := &goidc.GrantSession{
		ID: "random_session_id",
	}

	// When.
	err := manager.Save(context.Background(), session)

	// Then.
	for i := 0; i < 2; i++ {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(manager.Sessions) != 1 {
			t.Errorf("len(manager.Session) = %d, want 1", len(manager.Sessions))
		}
	}
}

func TestGetGrantSessionByTokenID_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager(1)
	sessionID := "random_session_id"
	tokenID := "random_token_id"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID:      sessionID,
		TokenID: tokenID,
	}

	// When.
	session, err := manager.SessionByTokenID(context.Background(), tokenID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestGrantSessionByRefreshTokenID(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager(1)
	sessionID := "random_session_id"
	refreshToken := "random_refresh_token"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID:           sessionID,
		RefreshToken: refreshToken,
	}

	// When.
	session, err := manager.SessionByRefreshToken(context.Background(), refreshToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestDeleteGrantSession(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager(1)
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID: sessionID,
	}

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.Sessions) != 0 {
		t.Errorf("len(manager.Session) = %d, want 0", len(manager.Sessions))
	}
}

func TestDeleteAuthnGrantSession(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager(1)
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
