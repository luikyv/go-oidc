package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOrUpdateAuthnSession_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
	session := &goidc.AuthnSession{
		ID: "random_session_id",
	}

	// When.
	err := manager.CreateOrUpdate(context.Background(), session)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 1, "there should be exactly one session")

	// When.
	err = manager.CreateOrUpdate(context.Background(), session)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 1, "there should be exactly one session")
}

func TestGetAuthnSessionByCallbackID_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	callbackID := "random_callback_id"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID:         sessionID,
		CallbackID: callbackID,
	}

	// When.
	session, err := manager.GetByCallbackID(context.Background(), callbackID)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, sessionID, session.ID, "invalid session ID")
}

func TestGetAuthnSessionByAuthorizationCode_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	authorizationCode := "random_authorization_code"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID:                sessionID,
		AuthorizationCode: authorizationCode,
	}

	// When.
	session, err := manager.GetByAuthorizationCode(context.Background(), authorizationCode)

	// Assert.
	require.Nil(t, err)
	assert.Equal(t, sessionID, session.ID, "invalid session ID")
}

func TestGetAuthnSessionByRequestURI_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
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
	require.Nil(t, err)
	assert.Equal(t, sessionID, session.ID, "invalid session ID")
}

func TestDeleteAuthnSession_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"
	manager.Sessions[sessionID] = &goidc.AuthnSession{
		ID: sessionID,
	}

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Sessions, 0, "the session should be deleted")
}

func TestDeleteAuthnSession_SessionDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewAuthnSessionManager()
	sessionID := "random_session_id"

	// When.
	err := manager.Delete(context.Background(), sessionID)

	// Then.
	require.Nil(t, err)
}
