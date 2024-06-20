package inmemory

import (
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
)

type InMemoryGrantSessionManager struct {
	Sessions map[string]models.GrantSession
}

func NewInMemoryGrantSessionManager() *InMemoryGrantSessionManager {
	return &InMemoryGrantSessionManager{
		Sessions: make(map[string]models.GrantSession),
	}
}

func (manager *InMemoryGrantSessionManager) CreateOrUpdate(grantSession models.GrantSession) error {
	manager.Sessions[grantSession.Id] = grantSession
	return nil
}

func (manager *InMemoryGrantSessionManager) Get(id string) (models.GrantSession, error) {
	grantSession, exists := manager.Sessions[id]
	if !exists {
		return models.GrantSession{}, models.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) getFirstToken(condition func(models.GrantSession) bool) (models.GrantSession, bool) {
	grantSessions := make([]models.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		grantSessions = append(grantSessions, t)
	}

	return unit.FindFirst(grantSessions, condition)
}

func (manager *InMemoryGrantSessionManager) GetByTokenId(tokenId string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.TokenId == tokenId
	})
	if !exists {
		return models.GrantSession{}, models.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) GetByRefreshToken(refreshToken string) (models.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t models.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return models.GrantSession{}, models.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) Delete(id string) error {
	delete(manager.Sessions, id)
	return nil
}
