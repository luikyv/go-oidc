package goidc

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func (testCtx TestContext) Request() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}

func (testCtx TestContext) Response() http.ResponseWriter {
	return httptest.NewRecorder()
}

func (testCtx TestContext) Logger() *slog.Logger {
	return slog.Default()
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
	assert.Greater(t, actual, expected-10, msgAndArgs)
	assert.Less(t, actual, expected+10, msgAndArgs)
}
