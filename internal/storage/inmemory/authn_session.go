package inmemory

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type AuthnSessionManager struct {
	Sessions map[string]*goidc.AuthnSession
}

func NewAuthnSessionManager() *AuthnSessionManager {
	return &AuthnSessionManager{
		Sessions: make(map[string]*goidc.AuthnSession),
	}
}

func (m *AuthnSessionManager) Save(
	_ context.Context,
	session *goidc.AuthnSession,
) error {
	m.Sessions[session.ID] = session
	return nil
}

func (m *AuthnSessionManager) GetByCallbackID(
	_ context.Context,
	callbackID string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.CallbackID == callbackID
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) GetByAuthorizationCode(
	_ context.Context,
	authorizationCode string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) GetByRequestURI(
	_ context.Context,
	requestURI string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := m.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.RequestURI == requestURI
	})
	if !exists {
		return nil, errors.New("entity not found")
	}

	return session, nil
}

func (m *AuthnSessionManager) Delete(_ context.Context, id string) error {
	delete(m.Sessions, id)
	return nil
}

func (m *AuthnSessionManager) getFirstSession(
	condition func(*goidc.AuthnSession) bool,
) (
	*goidc.AuthnSession,
	bool,
) {
	sessions := make([]*goidc.AuthnSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}
