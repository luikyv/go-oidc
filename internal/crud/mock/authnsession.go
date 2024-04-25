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
	manager.Sessions[session.Id] = session
	return nil
}

func (manager *MockedAuthnSessionManager) getFirstSession(condition func(models.AuthnSession) bool) (models.AuthnSession, bool) {
	sessions := make([]models.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}

	return unit.FindFirst(sessions, condition)
}

func (manager *MockedAuthnSessionManager) GetByCallbackId(callbackId string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.CallbackId == callbackId
	})
	if !exists {
		return models.AuthnSession{}, issues.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *MockedAuthnSessionManager) GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return models.AuthnSession{}, issues.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *MockedAuthnSessionManager) GetByRequestUri(requestUri string) (models.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.RequestUri == requestUri
	})
	if !exists {
		return models.AuthnSession{}, issues.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *MockedAuthnSessionManager) Delete(id string) error {
	delete(manager.Sessions, id)
	return nil
}
