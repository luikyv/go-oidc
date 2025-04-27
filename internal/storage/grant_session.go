package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type GrantSessionManager struct {
	Sessions map[string]*goidc.GrantSession
	mu       sync.RWMutex
	maxSize  int
}

func NewGrantSessionManager(maxSize int) *GrantSessionManager {
	return &GrantSessionManager{
		Sessions: make(map[string]*goidc.GrantSession),
		maxSize:  maxSize,
	}
}

func (m *GrantSessionManager) Save(_ context.Context, grantSession *goidc.GrantSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Sessions) >= m.maxSize {
		removeOldest(m.Sessions, func(gs *goidc.GrantSession) int {
			return gs.CreatedAtTimestamp
		})
	}

	m.Sessions[grantSession.ID] = grantSession
	return nil
}

func (m *GrantSessionManager) SessionByTokenID(_ context.Context, tokenID string) (*goidc.GrantSession, error) {
	grantSession, exists := m.firstSession(func(t *goidc.GrantSession) bool {
		return t.TokenID == tokenID
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return grantSession, nil
}

func (m *GrantSessionManager) SessionByRefreshTokenID(_ context.Context, id string) (*goidc.GrantSession, error) {
	grantSession, exists := m.firstSession(func(t *goidc.GrantSession) bool {
		return t.RefreshTokenID == id
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return grantSession, nil
}

func (m *GrantSessionManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Sessions, id)
	return nil
}

func (m *GrantSessionManager) DeleteByAuthCode(ctx context.Context, code string) error {
	grantSession, exists := m.firstSession(func(t *goidc.GrantSession) bool {
		return t.AuthCode == code
	})

	if !exists {
		return nil
	}

	return m.Delete(ctx, grantSession.ID)
}

func (m *GrantSessionManager) firstSession(condition func(*goidc.GrantSession) bool) (*goidc.GrantSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert the map to a slice of sessions.
	grantSessions := make([]*goidc.GrantSession, 0, len(m.Sessions))
	for _, t := range m.Sessions {
		grantSessions = append(grantSessions, t)
	}

	return findFirst(grantSessions, condition)
}

var _ goidc.GrantSessionManager = NewGrantSessionManager(0)
