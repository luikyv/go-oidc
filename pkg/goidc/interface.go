package goidc

import (
	"context"
	"net/http"
)

type Context interface {
	Request() *http.Request
	Response() http.ResponseWriter
	Client(clientID string) (*Client, error)
	// context.Context is embedded here as a shortcut to access the context in the request.
	context.Context
}

type ClientManager interface {
	Save(ctx context.Context, client *Client) error
	Get(ctx context.Context, id string) (*Client, error)
	Delete(ctx context.Context, id string) error
}

type GrantSessionManager interface {
	Save(ctx context.Context, grantSession *GrantSession) error
	GetByTokenID(ctx context.Context, tokenID string) (*GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionManager interface {
	Save(ctx context.Context, session *AuthnSession) error
	GetByCallbackID(ctx context.Context, callbackID string) (*AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (*AuthnSession, error)
	GetByRequestURI(ctx context.Context, requestURI string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}
