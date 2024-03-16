package mock

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type MockedAuthnSessionManager struct {
	sessions map[string]models.AuthnSession
}

func NewMockedAuthnSessionManager() *MockedAuthnSessionManager {
	return &MockedAuthnSessionManager{
		sessions: make(map[string]models.AuthnSession),
	}
}

func (manager *MockedAuthnSessionManager) CreateOrUpdate(session models.AuthnSession) error {
	manager.sessions[session.CallbackId] = session
	return nil
}

func (manager *MockedAuthnSessionManager) GetByCallbackId(callbackId string) (models.AuthnSession, error) {
	session, exists := manager.sessions[callbackId]
	if !exists {
		return models.AuthnSession{}, issues.EntityNotFoundError{Id: callbackId}
	}

	return session, nil
}

func (manager *MockedAuthnSessionManager) GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
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

func (manager *MockedAuthnSessionManager) Delete(id string) {
	delete(manager.sessions, id)
}
