package storage

import (
	"context"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

var _ goidc.AuthManager = &Manager{}
var _ goidc.DCRManager = &Manager{}
var _ goidc.OpenIDFedManager = &Manager{}
var _ goidc.PARManager = &Manager{}
var _ goidc.CIBAManager = &Manager{}
var _ goidc.DeviceAuthManager = &Manager{}
var _ goidc.RefreshTokenManager = &Manager{}
var _ goidc.GrantManager = &Manager{}
var _ goidc.LogoutManager = &Manager{}

type Manager struct {
	Sessions       map[string]*goidc.AuthnSession
	sessionMutex   sync.RWMutex
	Clients        map[string]*goidc.Client
	clientMutex    sync.RWMutex
	Grants         map[string]*goidc.Grant
	grantMutex     sync.RWMutex
	Tokens         map[string]*goidc.Token
	tokenMutex     sync.RWMutex
	LogoutSessions map[string]*goidc.LogoutSession
	logoutMutex    sync.RWMutex
	maxSize        int
}

func NewManager(maxSize int) *Manager {
	return &Manager{
		Sessions:       make(map[string]*goidc.AuthnSession),
		Clients:        make(map[string]*goidc.Client),
		Grants:         make(map[string]*goidc.Grant),
		Tokens:         make(map[string]*goidc.Token),
		LogoutSessions: make(map[string]*goidc.LogoutSession),
		maxSize:        maxSize,
	}
}

func (m *Manager) SaveSession(_ context.Context, as *goidc.AuthnSession) error {
	m.sessionMutex.Lock()
	defer m.sessionMutex.Unlock()

	if len(m.Sessions) >= m.maxSize {
		removeOldest(m.Sessions, func(s *goidc.AuthnSession) int {
			return s.CreatedAt
		})
	}

	m.Sessions[as.ID] = as
	return nil
}

func (m *Manager) Session(_ context.Context, id string) (*goidc.AuthnSession, error) {
	as, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.ID == id
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return as, nil
}

func (m *Manager) SessionByDeviceCode(_ context.Context, code string) (*goidc.AuthnSession, error) {
	as, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.DeviceCode == code
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return as, nil
}

func (m *Manager) SessionByPushedAuthReqID(_ context.Context, id string) (*goidc.AuthnSession, error) {
	as, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.PushedAuthReqID == id
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return as, nil
}

func (m *Manager) SessionByAuthReqID(_ context.Context, id string) (*goidc.AuthnSession, error) {
	as, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.AuthReqID == id
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return as, nil
}

func (m *Manager) SessionByUserCode(_ context.Context, code string) (*goidc.AuthnSession, error) {
	as, exists := m.firstSession(func(s *goidc.AuthnSession) bool {
		return s.UserCode == code
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return as, nil
}

func (m *Manager) DeleteSession(_ context.Context, id string) error {
	m.sessionMutex.Lock()
	defer m.sessionMutex.Unlock()

	delete(m.Sessions, id)
	return nil
}

func (m *Manager) firstSession(condition func(*goidc.AuthnSession) bool) (*goidc.AuthnSession, bool) {
	m.sessionMutex.RLock()
	defer m.sessionMutex.RUnlock()

	sessions := make([]*goidc.AuthnSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}

func (m *Manager) SaveClient(_ context.Context, c *goidc.Client) error {
	m.clientMutex.Lock()
	defer m.clientMutex.Unlock()

	if len(m.Clients) >= m.maxSize {
		removeOldest(m.Clients, func(c *goidc.Client) int { return c.CreatedAt })
	}

	m.Clients[c.ID] = c
	return nil
}

func (m *Manager) Client(_ context.Context, id string) (*goidc.Client, error) {
	m.clientMutex.RLock()
	defer m.clientMutex.RUnlock()

	c, exists := m.Clients[id]
	if !exists {
		return nil, goidc.ErrNotFound
	}

	// Make sure the content of jwks_uri is cleared from jwks when fetching the
	// client from the in memory storaged.
	if c.JWKSURI != "" {
		c.CacheJWKS(nil)
	}

	return c, nil
}

func (m *Manager) DeleteClient(_ context.Context, id string) error {
	m.clientMutex.Lock()
	defer m.clientMutex.Unlock()

	delete(m.Clients, id)
	return nil
}

func (m *Manager) SaveGrant(_ context.Context, grant *goidc.Grant) error {
	m.grantMutex.Lock()
	defer m.grantMutex.Unlock()

	if len(m.Grants) >= m.maxSize {
		removeOldest(m.Grants, func(g *goidc.Grant) int { return g.CreatedAt })
	}

	m.Grants[grant.ID] = grant
	return nil
}

func (m *Manager) Grant(_ context.Context, id string) (*goidc.Grant, error) {
	m.grantMutex.RLock()
	defer m.grantMutex.RUnlock()

	for _, g := range m.Grants {
		if g.ID == id {
			return g, nil
		}
	}

	return nil, goidc.ErrNotFound
}

func (m *Manager) GrantByAuthCode(_ context.Context, code string) (*goidc.Grant, error) {
	m.grantMutex.RLock()
	defer m.grantMutex.RUnlock()

	for _, g := range m.Grants {
		if g.AuthCode == code {
			return g, nil
		}
	}

	return nil, goidc.ErrNotFound
}

func (m *Manager) GrantByRefreshToken(_ context.Context, tkn string) (*goidc.Grant, error) {
	m.grantMutex.RLock()
	defer m.grantMutex.RUnlock()

	for _, g := range m.Grants {
		if g.RefreshToken == tkn {
			return g, nil
		}
	}

	return nil, goidc.ErrNotFound
}

func (m *Manager) GrantByAuthReqID(_ context.Context, id string) (*goidc.Grant, error) {
	m.grantMutex.RLock()
	defer m.grantMutex.RUnlock()

	for _, g := range m.Grants {
		if g.AuthReqID == id {
			return g, nil
		}
	}

	return nil, goidc.ErrNotFound
}

func (m *Manager) GrantByDeviceCode(_ context.Context, code string) (*goidc.Grant, error) {
	m.grantMutex.RLock()
	defer m.grantMutex.RUnlock()

	for _, g := range m.Grants {
		if g.DeviceCode == code {
			return g, nil
		}
	}

	return nil, goidc.ErrNotFound
}

func (m *Manager) DeleteGrant(_ context.Context, id string) error {
	m.grantMutex.Lock()
	defer m.grantMutex.Unlock()

	delete(m.Grants, id)
	return nil
}

func (m *Manager) SaveToken(_ context.Context, token *goidc.Token) error {
	m.tokenMutex.Lock()
	defer m.tokenMutex.Unlock()

	if len(m.Tokens) >= m.maxSize {
		removeOldest(m.Tokens, func(t *goidc.Token) int { return t.CreatedAt })
	}

	m.Tokens[token.ID] = token
	return nil
}

func (m *Manager) Token(_ context.Context, id string) (*goidc.Token, error) {
	m.tokenMutex.RLock()
	defer m.tokenMutex.RUnlock()

	token, exists := m.Tokens[id]
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return token, nil
}

func (m *Manager) DeleteToken(_ context.Context, id string) error {
	m.tokenMutex.Lock()
	defer m.tokenMutex.Unlock()

	delete(m.Tokens, id)
	return nil
}

func (m *Manager) DeleteTokenByGrantID(_ context.Context, grantID string) error {
	m.tokenMutex.Lock()
	defer m.tokenMutex.Unlock()

	for id, token := range m.Tokens {
		if token.GrantID == grantID {
			delete(m.Tokens, id)
		}
	}

	return nil
}

func (m *Manager) SaveLogoutSession(_ context.Context, session *goidc.LogoutSession) error {
	m.logoutMutex.Lock()
	defer m.logoutMutex.Unlock()

	if len(m.LogoutSessions) >= m.maxSize {
		removeOldest(m.LogoutSessions, func(s *goidc.LogoutSession) int { return s.CreatedAt })
	}

	m.LogoutSessions[session.ID] = session
	return nil
}

func (m *Manager) LogoutSession(_ context.Context, id string) (*goidc.LogoutSession, error) {
	m.logoutMutex.RLock()
	defer m.logoutMutex.RUnlock()

	sessions := make([]*goidc.LogoutSession, 0, len(m.LogoutSessions))
	for _, s := range m.LogoutSessions {
		sessions = append(sessions, s)
	}

	session, exists := findFirst(sessions, func(s *goidc.LogoutSession) bool {
		return s.ID == id
	})
	if !exists {
		return nil, goidc.ErrNotFound
	}

	return session, nil
}

func (m *Manager) DeleteLogoutSession(_ context.Context, id string) error {
	m.logoutMutex.Lock()
	defer m.logoutMutex.Unlock()

	delete(m.LogoutSessions, id)
	return nil
}

// findFirst returns the first element in a slice for which the condition is true.
// If no element is found, 'ok' is set to false.
func findFirst[T any](slice []T, condition func(T) bool) (element T, ok bool) {
	for _, element = range slice {
		if condition(element) {
			return element, true
		}
	}

	return element, false
}

func removeOldest[T any](m map[string]T, createdAtFunc func(T) int) {
	var oldestKey string
	var oldestCreatedAt int

	for key, value := range m {
		createdAt := createdAtFunc(value)
		if oldestCreatedAt == 0 || createdAt < oldestCreatedAt {
			oldestKey = key
			oldestCreatedAt = createdAt
		}
	}

	delete(m, oldestKey)
}
