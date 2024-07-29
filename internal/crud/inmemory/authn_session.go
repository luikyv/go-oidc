package inmemory

import (
	"context"

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

func (manager *AuthnSessionManager) Save(
	_ context.Context,
	session *goidc.AuthnSession,
) error {
	manager.Sessions[session.ID] = session
	return nil
}

func (manager *AuthnSessionManager) GetByCallbackID(
	_ context.Context,
	callbackID string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := manager.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.CallbackID == callbackID
	})
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *AuthnSessionManager) GetByAuthorizationCode(
	_ context.Context,
	authorizationCode string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := manager.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *AuthnSessionManager) GetByRequestURI(
	_ context.Context,
	requestURI string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, exists := manager.getFirstSession(func(s *goidc.AuthnSession) bool {
		return s.RequestURI == requestURI
	})
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *AuthnSessionManager) Delete(_ context.Context, id string) error {
	delete(manager.Sessions, id)
	return nil
}

func (manager *AuthnSessionManager) getFirstSession(
	condition func(*goidc.AuthnSession) bool,
) (
	*goidc.AuthnSession,
	bool,
) {
	sessions := make([]*goidc.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}
