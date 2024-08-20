package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOrUpdateGrantSessionSession_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager()
	session := &goidc.GrantSession{
		ID: "random_session_id",
	}

	// When.
	err := manager.Save(context.Background(), session)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 1, "there should be exactly one session")

	// When.
	err = manager.Save(context.Background(), session)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 1, "there should be exactly one session")
}

func TestGetGrantSessionByTokenID_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager()
	sessionID := "random_session_id"
	tokenID := "random_token_id"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID:      sessionID,
		TokenID: tokenID,
	}

	// When.
	session, err := manager.GetByTokenID(context.Background(), tokenID)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, sessionID, session.ID, "invalid session ID")
}

func TestGetGrantSessionByRefreshToken_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager()
	sessionID := "random_session_id"
	refreshToken := "random_refresh_token"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID:           sessionID,
		RefreshToken: refreshToken,
	}

	// When.
	session, err := manager.GetByRefreshToken(context.Background(), refreshToken)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, sessionID, session.ID, "invalid session ID")
}

func TestDeleteGrantSession_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager()
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.GrantSession{
		ID: sessionID,
	}

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 0, "there shouldn't be any sessions")
}

func TestDeleteAuthnGrantSession_SessionDoesNotExist(t *testing.T) {
	// Given.
	manager := storage.NewGrantSessionManager()
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	require.Nil(t, err)
}
