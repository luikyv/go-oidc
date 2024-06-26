package inmemory

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
)

type InMemoryAuthnSessionManager struct {
	Sessions map[string]goidc.AuthnSession
}

func NewInMemoryAuthnSessionManager() *InMemoryAuthnSessionManager {
	return &InMemoryAuthnSessionManager{
		Sessions: make(map[string]goidc.AuthnSession),
	}
}

func (manager *InMemoryAuthnSessionManager) CreateOrUpdate(_ context.Context, session goidc.AuthnSession) error {
	manager.Sessions[session.Id] = session
	return nil
}

func (manager *InMemoryAuthnSessionManager) getFirstSession(condition func(goidc.AuthnSession) bool) (goidc.AuthnSession, bool) {
	sessions := make([]goidc.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}

	return findFirst(sessions, condition)
}

func (manager *InMemoryAuthnSessionManager) GetByCallbackId(_ context.Context, callbackId string) (goidc.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s goidc.AuthnSession) bool {
		return s.CallbackId == callbackId
	})
	if !exists {
		return goidc.AuthnSession{}, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByAuthorizationCode(_ context.Context, authorizationCode string) (goidc.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s goidc.AuthnSession) bool {
		return s.AuthorizationCode == authorizationCode
	})
	if !exists {
		return goidc.AuthnSession{}, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) GetByRequestUri(_ context.Context, requestUri string) (goidc.AuthnSession, error) {
	session, exists := manager.getFirstSession(func(s goidc.AuthnSession) bool {
		return s.RequestUri == requestUri
	})
	if !exists {
		return goidc.AuthnSession{}, goidc.ErrorEntityNotFound
	}

	return session, nil
}

func (manager *InMemoryAuthnSessionManager) Delete(_ context.Context, id string) error {
	delete(manager.Sessions, id)
	return nil
}
