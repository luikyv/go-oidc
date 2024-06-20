package inmemory

import (
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

func (manager *InMemoryAuthnSessionManager) CreateOrUpdate(session models.AuthnSession) error {
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

func (manager *InMemoryAuthnSessionManager) GetByCallbackId(callbackId string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.CallbackId == callbackId
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByRequestUri(requestUri string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.RequestUri == requestUri
	})
	if !exists {
		return models.AuthnSession{}, models.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) Delete(id string) error {
	delete(manager.Sessions, id)
	return nil
}
