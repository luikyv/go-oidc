package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type MockedGrantSessionManager struct {
	GrantSessions map[string]models.GrantSession
}

func NewMockedGrantSessionManager() *MockedGrantSessionManager {
	return &MockedGrantSessionManager{
		GrantSessions: make(map[string]models.GrantSession),
	}
}

func (manager *MockedGrantSessionManager) CreateOrUpdate(grantSession models.GrantSession) error {
	manager.GrantSessions[grantSession.Id] = grantSession
	return nil
}

func (manager *MockedGrantSessionManager) Get(id string) (models.GrantSession, error) {
	grantSession, exists := manager.GrantSessions[id]
	if !exists {
		return models.GrantSession{}, issues.EntityNotFoundError{Id: id}
	}

	return grantSession, nil
}

func (manager *MockedGrantSessionManager) getFirstToken(condition func(models.GrantSession) bool) (models.GrantSession, bool) {
	grantSessions := make([]models.GrantSession, 0, len(manager.GrantSessions))
	for _, t := range manager.GrantSessions {
		grantSessions = append(grantSessions, t)
	}

	return unit.FindFirst(grantSessions, condition)
}

func (manager *MockedGrantSessionManager) GetByTokenId(tokenId string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.TokenId == tokenId
	})
	if !exists {
		return models.GrantSession{}, issues.EntityNotFoundError{Id: tokenId}
	}

	return grantSession, nil
}

func (manager *MockedGrantSessionManager) GetByRefreshToken(refreshToken string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return models.GrantSession{}, issues.EntityNotFoundError{Id: refreshToken}
	}

	return grantSession, nil
}

func (manager *MockedGrantSessionManager) Delete(id string) error {
	delete(manager.GrantSessions, id)
	return nil
}
