package mock

import (
	"github.com/luikymagno/auth-server/internal/crud"
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

func (manager *MockedAuthnSessionManager) CreateOrUpdate(session models.AuthnSession, ch chan error) {
	manager.Sessions[session.Id] = session
	ch <- nil
}

func (manager *MockedAuthnSessionManager) getFirstSession(condition func(models.AuthnSession) bool) (models.AuthnSession, bool) {
	sessions := make([]models.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}

	return unit.FindFirst(sessions, condition)
}

func (manager *MockedAuthnSessionManager) GetByCallbackId(callbackId string, ch chan crud.AuthnSessionGetResult) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.CallbackId == callbackId
	})
	if !exists {
		ch <- crud.AuthnSessionGetResult{
			Session: models.AuthnSession{},
			Error:   issues.EntityNotFoundError{Id: callbackId},
		}
		return
	}

	ch <- crud.AuthnSessionGetResult{
		Session: session,
		Error:   nil,
	}
}

func (manager *MockedAuthnSessionManager) GetByAuthorizationCode(authorizationCode string, ch chan crud.AuthnSessionGetResult) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		ch <- crud.AuthnSessionGetResult{
			Session: models.AuthnSession{},
			Error:   issues.EntityNotFoundError{Id: authorizationCode},
		}
		return
	}

	ch <- crud.AuthnSessionGetResult{
		Session: session,
		Error:   nil,
	}
}

func (manager *MockedAuthnSessionManager) GetByRequestUri(requestUri string, ch chan crud.AuthnSessionGetResult) {
	session, exists := manager.getFirstSession(func(s models.AuthnSession) bool {
		return s.RequestUri == requestUri
	})
	if !exists {
		ch <- crud.AuthnSessionGetResult{
			Session: models.AuthnSession{},
			Error:   issues.EntityNotFoundError{Id: requestUri},
		}
		return
	}

	ch <- crud.AuthnSessionGetResult{
		Session: session,
		Error:   nil,
	}
}

func (manager *MockedAuthnSessionManager) Delete(id string) {
	delete(manager.Sessions, id)
}
