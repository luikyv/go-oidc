package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSaveGrant(t *testing.T) {
	// Given.
	manager := storage.NewGrantManager(1)
	grant := &goidc.Grant{
		ID: "random_session_id",
	}

	// When.
	err := manager.Save(context.Background(), grant)

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

func TestGrantByRefreshToken(t *testing.T) {
	// Given.
	manager := storage.NewGrantManager(1)
	sessionID := "random_session_id"
	refreshToken := "random_refresh_token"
	manager.Sessions[sessionID] = &goidc.Grant{
		ID:           sessionID,
		RefreshToken: refreshToken,
	}

	// When.
	session, err := manager.GrantByRefreshToken(context.Background(), refreshToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("ID = %s, want %s", session.ID, sessionID)
	}
}

func TestDeleteGrant(t *testing.T) {
	// Given.
	manager := storage.NewGrantManager(1)
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.Grant{
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

func TestDeleteGrant_NotFound(t *testing.T) {
	// Given.
	manager := storage.NewGrantManager(1)
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
