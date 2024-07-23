package inmemory

import (
	"context"

	"github.com/luikyv/goidc/pkg/goidc"
)

type GrantSessionManager struct {
	Sessions map[string]*goidc.GrantSession
}

func NewGrantSessionManager() *GrantSessionManager {
	return &GrantSessionManager{
		Sessions: make(map[string]*goidc.GrantSession),
	}
}

func (manager *GrantSessionManager) Save(_ context.Context, grantSession *goidc.GrantSession) error {
	manager.Sessions[grantSession.ID] = grantSession
	return nil
}

func (manager *GrantSessionManager) GetByTokenID(_ context.Context, tokenID string) (*goidc.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t *goidc.GrantSession) bool {
		return t.TokenID == tokenID
	})
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *GrantSessionManager) GetByRefreshToken(_ context.Context, refreshToken string) (*goidc.GrantSession, error) {
	grantSession, exists := manager.getFirstToken(func(t *goidc.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return grantSession, nil
}

func (manager *GrantSessionManager) Delete(_ context.Context, id string) error {
	delete(manager.Sessions, id)
	return nil
}

func (manager *GrantSessionManager) getFirstToken(condition func(*goidc.GrantSession) bool) (*goidc.GrantSession, bool) {
	grantSessions := make([]*goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		grantSessions = append(grantSessions, t)
	}

	return findFirst(grantSessions, condition)
}
