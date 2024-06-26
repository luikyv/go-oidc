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
	RenderHtml(html string, params any)
	RenderHtmlTemplate(tmpl *template.Template, params any)
	GetLogger() *slog.Logger
	context.Context
}

type ClientManager interface {
	Create(ctx context.Context, client Client) error
	Update(ctx context.Context, id string, client Client) error
	Get(ctx context.Context, id string) (Client, error)
	Delete(ctx context.Context, id string) error
}

type GrantSessionManager interface {
	CreateOrUpdate(ctx context.Context, grantSession GrantSession) error
	Get(ctx context.Context, id string) (GrantSession, error)
	GetByTokenId(ctx context.Context, tokenId string) (GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(ctx context.Context, session AuthnSession) error
	GetByCallbackId(ctx context.Context, callbackId string) (AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (AuthnSession, error)
	GetByRequestUri(ctx context.Context, requestUri string) (AuthnSession, error)
	Delete(ctx context.Context, id string) error
}
