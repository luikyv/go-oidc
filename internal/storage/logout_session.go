package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

var _ goidc.LogoutSessionManager = NewLogoutSessionManager(0)

type LogoutSessionManager struct {
	Sessions map[string]*goidc.LogoutSession
	mu       sync.RWMutex
	maxSize  int
}

func NewLogoutSessionManager(maxSize int) *LogoutSessionManager {
	return &LogoutSessionManager{
		Sessions: make(map[string]*goidc.LogoutSession),
		maxSize:  maxSize,
	}
}

func (m *LogoutSessionManager) Save(_ context.Context, session *goidc.LogoutSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Sessions) >= m.maxSize {
		removeOldest(m.Sessions, func(s *goidc.LogoutSession) int {
			return s.CreatedAtTimestamp
		})
	}

	m.Sessions[session.ID] = session
	return nil
}

func (m *LogoutSessionManager) SessionByCallbackID(_ context.Context, callbackID string) (*goidc.LogoutSession, error) {
	session, exists := m.firstSession(func(s *goidc.LogoutSession) bool {
		return s.CallbackID == callbackID
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *LogoutSessionManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Sessions, id)
	return nil
}

func (m *LogoutSessionManager) firstSession(condition func(*goidc.LogoutSession) bool) (*goidc.LogoutSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert the map to a slice of sessions.
	sessions := make([]*goidc.LogoutSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}
