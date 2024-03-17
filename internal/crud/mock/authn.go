package mock

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type MockedAuthnSessionManager struct {
	Sessions map[string]models.AuthnSession
}

func NewMockedAuthnSessionManager() *MockedAuthnSessionManager {
	return &MockedAuthnSessionManager{
		Sessions: make(map[string]models.AuthnSession),
	}
}

func (manager *MockedAuthnSessionManager) CreateOrUpdate(session models.AuthnSession) error {
	manager.Sessions[session.CallbackId] = session
	return nil
}

func (manager *MockedAuthnSessionManager) GetByCallbackId(callbackId string) (models.AuthnSession, error) {
	session, exists := manager.Sessions[callbackId]
	if !exists {
		return models.AuthnSession{}, issues.EntityNotFoundError{Id: callbackId}
	}

	return session, nil
}

func (manager *MockedAuthnSessionManager) GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
	sessions := make([]models.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
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
	delete(manager.Sessions, id)
}
