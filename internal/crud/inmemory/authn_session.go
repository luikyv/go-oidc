package inmemory

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
)

type InMemoryAuthnSessionManager struct {
	Sessions map[string]models.AuthnSession
}

func NewInMemoryAuthnSessionManager() *InMemoryAuthnSessionManager {
	return &InMemoryAuthnSessionManager{
		Sessions: make(map[string]models.AuthnSession),
	}
}

func (manager *InMemoryAuthnSessionManager) CreateOrUpdate(_ context.Context, session models.AuthnSession) error {
	manager.Sessions[session.Id] = session
	return nil
}

func (manager *InMemoryAuthnSessionManager) getFirstSession(condition func(models.AuthnSession) bool) (models.AuthnSession, bool) {
	sessions := make([]models.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}

	return unit.FindFirst(sessions, condition)
}

func (manager *InMemoryAuthnSessionManager) GetByCallbackId(_ context.Context, callbackId string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.CallbackId == callbackId
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByAuthorizationCode(_ context.Context, authorizationCode string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByRequestUri(_ context.Context, requestUri string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.RequestUri == requestUri
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) Delete(_ context.Context, id string) error {
	delete(manager.Sessions, id)
	return nil
}
