package goidc

import (
	"context"
	"net/http"
)

type Context interface {
	Request() *http.Request
	Response() http.ResponseWriter
	// AuthnHints provides a list of hints to fulfill the authentication flow successfully.
	// The authentication flow can still finished successfully if the hints are not followed, but it's recommended
	// to evaluate them and modify the session accordingly.
	AuthnHints(*UserInfo, *AuthnSession) ([]AuthnHint, error)
}

type ClientManager interface {
	CreateOrUpdate(ctx context.Context, client *Client) error
	Get(ctx context.Context, id string) (*Client, error)
	Delete(ctx context.Context, id string) error
}

type GrantSessionManager interface {
	CreateOrUpdate(ctx context.Context, grantSession *GrantSession) error
	GetByTokenID(ctx context.Context, tokenID string) (*GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(ctx context.Context, session *AuthnSession) error
	GetByCallbackID(ctx context.Context, callbackID string) (*AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (*AuthnSession, error)
	GetByRequestURI(ctx context.Context, requestURI string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}
