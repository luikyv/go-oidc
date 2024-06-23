package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/internal/models"
)

func TestCreateOrUpdateGrantSessionSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	session := models.GrantSession{
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

func TestGetGrantSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionId := "random_session_id"
	manager.Sessions[sessionId] = models.GrantSession{
		Id: sessionId,
	}

	// Then.
	session, err := manager.Get(context.Background(), sessionId)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetGrantSessionByTokenId_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionId := "random_session_id"
	tokenId := "random_token_id"
	manager.Sessions[sessionId] = models.GrantSession{
		Id:      sessionId,
		TokenId: tokenId,
	}

	// Then.
	session, err := manager.GetByTokenId(context.Background(), tokenId)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestGetGrantSessionByRefreshToken_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionId := "random_session_id"
	refreshToken := "random_refresh_token"
	manager.Sessions[sessionId] = models.GrantSession{
		Id:           sessionId,
		RefreshToken: refreshToken,
	}

	// Then.
	session, err := manager.GetByRefreshToken(context.Background(), refreshToken)

	// Assert.
	if err != nil {
		t.Error("error when getting the session", err)
	}

	if session.Id != sessionId {
		t.Error("invalid session ID")
	}
}

func TestDeleteGrantSession_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionId := "random_session_id"
	manager.Sessions[sessionId] = models.GrantSession{
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

func TestDeleteAuthnGrantSession_SessionDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryGrantSessionManager()
	sessionId := "random_session_id"

	// Then.
	err := manager.Delete(context.Background(), sessionId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the session", err)
	}
}
