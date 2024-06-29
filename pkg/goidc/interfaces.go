package goidc

import (
	"context"
	"crypto/x509"
	"html/template"
	"log/slog"
)

type Context interface {
	GetHost() string
	GetHeader(header string) (headerValue string, ok bool)
	GetFormParam(param string) (formValue string)
	GetSecureClientCertificate() (secureClientCert *x509.Certificate, ok bool)
	GetClientCertificate() (clientCert *x509.Certificate, ok bool)
	RenderHTML(html string, params any) error
	RenderHTMLTemplate(tmpl *template.Template, params any) error
	GetLogger() *slog.Logger
	context.Context
}

type ClientManager interface {
	CreateOrUpdate(ctx context.Context, client Client) error
	Get(ctx context.Context, id string) (Client, error)
	Delete(ctx context.Context, id string) error
}

type GrantSessionManager interface {
	CreateOrUpdate(ctx context.Context, grantSession GrantSession) error
	GetByTokenID(ctx context.Context, tokenID string) (GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(ctx context.Context, session AuthnSession) error
	GetByCallbackID(ctx context.Context, callbackID string) (AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (AuthnSession, error)
	GetByRequestURI(ctx context.Context, requestURI string) (AuthnSession, error)
	Delete(ctx context.Context, id string) error
}
