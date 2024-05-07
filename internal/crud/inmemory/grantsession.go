package inmemory

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

type InMemoryGrantSessionManager struct {
	GrantSessions map[string]models.GrantSession
}

func NewInMemoryGrantSessionManager() *InMemoryGrantSessionManager {
	return &InMemoryGrantSessionManager{
		GrantSessions: make(map[string]models.GrantSession),
	}
}

func (manager *InMemoryGrantSessionManager) CreateOrUpdate(grantSession models.GrantSession) error {
	manager.GrantSessions[grantSession.Id] = grantSession
	return nil
}

func (manager *InMemoryGrantSessionManager) Get(id string) (models.GrantSession, error) {
	grantSession, exists := manager.GrantSessions[id]
	if !exists {
		return models.GrantSession{}, issues.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) getFirstToken(condition func(models.GrantSession) bool) (models.GrantSession, bool) {
	grantSessions := make([]models.GrantSession, 0, len(manager.GrantSessions))
	for _, t := range manager.GrantSessions {
		grantSessions = append(grantSessions, t)
	}

	return unit.FindFirst(grantSessions, condition)
}

func (manager *InMemoryGrantSessionManager) GetByTokenId(tokenId string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.TokenId == tokenId
	})
	if !exists {
		return models.GrantSession{}, issues.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) GetByRefreshToken(refreshToken string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return models.GrantSession{}, issues.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) Delete(id string) error {
	delete(manager.GrantSessions, id)
	return nil
}
