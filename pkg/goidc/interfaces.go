package goidc

import (
	"context"
	"log/slog"
	"net/http"
)

// TODO: Remove unused fields.
type Context interface {
	Issuer() string
	Request() *http.Request
	Response() http.ResponseWriter
	Logger() *slog.Logger
	Scopes() Scopes
	context.Context
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
