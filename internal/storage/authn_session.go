package storage

import (
	"context"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type AuthnSessionManager struct {
	Sessions map[string]*goidc.AuthnSession
	mu       sync.RWMutex
	maxSize  int
}

func NewAuthnSessionManager(maxSize int) *AuthnSessionManager {
	return &AuthnSessionManager{
		Sessions: make(map[string]*goidc.AuthnSession),
		maxSize:  maxSize,
	}
}

func (m *AuthnSessionManager) Save(_ context.Context, session *goidc.AuthnSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Sessions) >= m.maxSize {
		removeOldest(m.Sessions, func(s *goidc.AuthnSession) int {
			return s.CreatedAtTimestamp
		})
	}

	m.Sessions[session.ID] = session
	return nil
}

func (m *AuthnSessionManager) SessionByCallbackID(_ context.Context, callbackID string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.CallbackID == callbackID
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByAuthCode(_ context.Context, authorizationCode string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.AuthCode == authorizationCode
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByPARID(_ context.Context, requestURI string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.PARID == requestURI
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByCIBAID(_ context.Context, id string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.CIBAID == id
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByDeviceCode(_ context.Context, code string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.DeviceCode == code
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) SessionByUserCode(_ context.Context, code string) (*goidc.AuthnSession, error) {
	session, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.UserCode == code
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *AuthnSessionManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Sessions, id)
	return nil
}

var _ goidc.AuthnSessionManager = NewAuthnSessionManager(0)

func (m *AuthnSessionManager) firstSession(condition func(*goidc.AuthnSession) bool) (*goidc.AuthnSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert the map to a slice of sessions.
	sessions := make([]*goidc.AuthnSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}

