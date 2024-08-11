package inmemory

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type GrantSessionManager struct {
	Sessions map[string]*goidc.GrantSession
}

func NewGrantSessionManager() *GrantSessionManager {
	return &GrantSessionManager{
		Sessions: make(map[string]*goidc.GrantSession),
	}
}

func (m *GrantSessionManager) Save(_ context.Context, grantSession *goidc.GrantSession) error {
	m.Sessions[grantSession.ID] = grantSession
	return nil
}

func (m *GrantSessionManager) GetByTokenID(_ context.Context, tokenID string) (*goidc.GrantSession, error) {
	grantSession, exists := m.getFirstToken(func(t *goidc.GrantSession) bool {
		return t.TokenID == tokenID
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return grantSession, nil
}

func (m *GrantSessionManager) GetByRefreshToken(_ context.Context, refreshToken string) (*goidc.GrantSession, error) {
	grantSession, exists := m.getFirstToken(func(t *goidc.GrantSession) bool {
		return t.RefreshToken == refreshToken
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return grantSession, nil
}

func (m *GrantSessionManager) Delete(_ context.Context, id string) error {
	delete(m.Sessions, id)
	return nil
}

func (m *GrantSessionManager) getFirstToken(condition func(*goidc.GrantSession) bool) (*goidc.GrantSession, bool) {
	grantSessions := make([]*goidc.GrantSession, 0, len(m.Sessions))
	for _, t := range m.Sessions {
		grantSessions = append(grantSessions, t)
	}

	return findFirst(grantSessions, condition)
}
