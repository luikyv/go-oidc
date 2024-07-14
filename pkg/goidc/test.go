package goidc

import (
	"crypto/x509"
	"html/template"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestContext struct {
	OAuthScopes Scopes
}

func (testCtx TestContext) Issuer() string {
	return ""
}

func (testCtx TestContext) Header(header string) (headerValue string, ok bool) {
	return "", false
}

func (testCtx TestContext) FormParam(param string) (formValue string) {
	return ""
}

func (testCtx TestContext) SecureClientCertificate() (secureClientCert *x509.Certificate, ok bool) {
	return nil, false
}

func (testCtx TestContext) ClientCertificate() (clientCert *x509.Certificate, ok bool) {
	return nil, false
}

func (testCtx TestContext) RenderHTML(html string, params any) error {
	return nil
}

func (testCtx TestContext) RenderHTMLTemplate(tmpl *template.Template, params any) error {
	return nil
}

func (testCtx TestContext) Logger() *slog.Logger {
	return nil
}

func (testCtx TestContext) Scopes() Scopes {
	return testCtx.OAuthScopes
}

func (testCtx TestContext) Deadline() (deadline time.Time, ok bool) {
	return time.Now().Add(24 * time.Hour), false
}

func (testCtx TestContext) Done() <-chan struct{} {
	return nil
}

func (testCtx TestContext) Err() error {
	return nil
}

func (testCtx TestContext) Value(key any) any {
	return nil
}

func NewTestContext(scopes Scopes) Context {
	return TestContext{
		OAuthScopes: scopes,
	}
}

func AssertTimestampWithin(t *testing.T, expected int, actual int, msgAndArgs ...any) {
	assert.Greater(t, actual, expected-1, msgAndArgs)
	assert.Less(t, actual, expected+1, msgAndArgs)
}
