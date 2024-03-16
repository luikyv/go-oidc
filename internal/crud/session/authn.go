package session

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type AuthnSessionManager interface {
	CreateOrUpdate(session models.AuthnSession) error
	GetByCallbackId(callbackId string) (models.AuthnSession, error)
	GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error)
	Delete(id string)
}

type InMemoryAuthnSessionManager struct {
	sessions map[string]models.AuthnSession
}

func NewInMemoryAuthnSessionManager() *InMemoryAuthnSessionManager {
	return &InMemoryAuthnSessionManager{
		sessions: make(map[string]models.AuthnSession),
	}
}

func (manager *InMemoryAuthnSessionManager) CreateOrUpdate(session models.AuthnSession) error {
	manager.sessions[session.CallbackId] = session
	return nil
}

func (manager *InMemoryAuthnSessionManager) GetByCallbackId(callbackId string) (models.AuthnSession, error) {
	session, exists := manager.sessions[callbackId]
	if !exists {
		return models.AuthnSession{}, issues.EntityNotFoundError{Id: callbackId}
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
	sessions := make([]models.AuthnSession, len(manager.sessions))
	for _, s := range manager.sessions {
		sessions = append(sessions, s)
	}

	session, exists := unit.FindFirst(sessions, func(s models.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return models.AuthnSession{}, issues.EntityNotFoundError{Id: authorizationCode}
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) Delete(id string) {
	delete(manager.sessions, id)
}
