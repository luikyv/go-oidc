package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type GrantManager struct {
	Sessions map[string]*goidc.Grant
	mu       sync.RWMutex
	maxSize  int
}

func NewGrantManager(maxSize int) *GrantManager {
	return &GrantManager{
		Sessions: make(map[string]*goidc.Grant),
		maxSize:  maxSize,
	}
}

func (m *GrantManager) Save(_ context.Context, grant *goidc.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Sessions) >= m.maxSize {
		removeOldest(m.Sessions, func(gs *goidc.Grant) int {
			return gs.CreatedAtTimestamp
		})
	}

	m.Sessions[grant.ID] = grant
	return nil
}

func (m *GrantManager) ByID(_ context.Context, id string) (*goidc.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grant, exists := m.Sessions[id]
	if !exists {
		return nil, errors.New("entity not found")
	}
	return grant, nil
}

func (m *GrantManager) SessionByRefreshToken(_ context.Context, tkn string) (*goidc.Grant, error) {
	grant, exists := m.firstSession(func(t *goidc.Grant) bool {
		return t.RefreshToken == tkn
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return grant, nil
}

func (m *GrantManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Sessions, id)
	return nil
}

func (m *GrantManager) DeleteByAuthCode(ctx context.Context, code string) error {
	grant, exists := m.firstSession(func(t *goidc.Grant) bool {
		return t.AuthCode == code
	})

	if !exists {
		return nil
	}

	return m.Delete(ctx, grant.ID)
}

func (m *GrantManager) firstSession(condition func(*goidc.Grant) bool) (*goidc.Grant, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert the map to a slice of sessions.
	grants := make([]*goidc.Grant, 0, len(m.Sessions))
	for _, t := range m.Sessions {
		grants = append(grants, t)
	}

	return findFirst(grants, condition)
}

var _ goidc.GrantManager = NewGrantManager(0)
