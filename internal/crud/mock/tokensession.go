package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type MockedTokenSessionManager struct {
	TokenSessions map[string]models.TokenSession
}

func NewMockedTokenSessionManager() *MockedTokenSessionManager {
	return &MockedTokenSessionManager{
		TokenSessions: make(map[string]models.TokenSession),
	}
}

func (manager *MockedTokenSessionManager) CreateOrUpdate(tokenSession models.TokenSession) error {
	manager.TokenSessions[tokenSession.Id] = tokenSession
	return nil
}

func (manager *MockedTokenSessionManager) Get(id string) (models.TokenSession, error) {
	tokenSession, exists := manager.TokenSessions[id]
	if !exists {
		return models.TokenSession{}, issues.EntityNotFoundError{Id: id}
	}

	return tokenSession, nil
}

func (manager *MockedTokenSessionManager) getFirstToken(condition func(models.TokenSession) bool) (models.TokenSession, bool) {
	tokenSessions := make([]models.TokenSession, 0, len(manager.TokenSessions))
	for _, t := range manager.TokenSessions {
		tokenSessions = append(tokenSessions, t)
	}

	return unit.FindFirst(tokenSessions, condition)
}

func (manager *MockedTokenSessionManager) GetByRefreshToken(refreshToken string) (models.TokenSession, error) {
	tokenSession, exists := manager.getFirstToken(func(t models.TokenSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return models.TokenSession{}, issues.EntityNotFoundError{Id: refreshToken}
	}

	return tokenSession, nil
}

func (manager *MockedTokenSessionManager) Delete(id string) error {
	delete(manager.TokenSessions, id)
	return nil
}
