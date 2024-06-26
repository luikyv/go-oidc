package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestCreateOrUpdateGrantSessionSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	session := goidc.GrantSession{
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

func TestGetGrantSessionByTokenID_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionID := "random_session_id"
	tokenID := "random_token_id"
	manager.Sessions[sessionID] = goidc.GrantSession{
		ID:      sessionID,
		TokenID: tokenID,
	}

	// Then.
	session, err := manager.GetByTokenID(context.Background(), tokenID)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.ID != sessionID {
		t.Error("invalid session ID")
	}
}

func TestGetGrantSessionByRefreshToken_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionID := "random_session_id"
	refreshToken := "random_refresh_token"
	manager.Sessions[sessionID] = goidc.GrantSession{
		ID:           sessionID,
		RefreshToken: refreshToken,
	}

	// Then.
	session, err := manager.GetByRefreshToken(context.Background(), refreshToken)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.ID != sessionID {
		t.Error("invalid session ID")
	}
}

func TestDeleteGrantSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = goidc.GrantSession{
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

func TestDeleteAuthnGrantSession_SessionDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionID := "random_session_id"

	// Then.
	err := manager.Delete(context.Background(), sessionID)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}
}
