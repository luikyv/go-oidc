package inmemory

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
)

type InMemoryGrantSessionManager struct {
	Sessions map[string]goidc.GrantSession
}

func NewInMemoryGrantSessionManager() *InMemoryGrantSessionManager {
	return &InMemoryGrantSessionManager{
		Sessions: make(map[string]goidc.GrantSession),
	}
}

func (manager *InMemoryGrantSessionManager) CreateOrUpdate(_ context.Context, grantSession goidc.GrantSession) error {
	manager.Sessions[grantSession.Id] = grantSession
	return nil
}

func (manager *InMemoryGrantSessionManager) Get(_ context.Context, id string) (goidc.GrantSession, error) {
	grantSession, exists := manager.Sessions[id]
	if !exists {
		return goidc.GrantSession{}, goidc.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) getFirstToken(condition func(goidc.GrantSession) bool) (goidc.GrantSession, bool) {
	grantSessions := make([]goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		grantSessions = append(grantSessions, t)
	}

	return findFirst(grantSessions, condition)
}

func (manager *InMemoryGrantSessionManager) GetByTokenId(_ context.Context, tokenId string) (goidc.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t goidc.GrantSession) bool {
		return t.TokenId == tokenId
	})
	if !exists {
		return goidc.GrantSession{}, goidc.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) GetByRefreshToken(_ context.Context, refreshToken string) (goidc.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t goidc.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return goidc.GrantSession{}, goidc.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *InMemoryGrantSessionManager) Delete(_ context.Context, id string) error {
	delete(manager.Sessions, id)
	return nil
}
