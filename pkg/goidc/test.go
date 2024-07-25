package goidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestContext struct {
	OAuthScopes Scopes
	Context     context.Context
}

func (testCtx TestContext) Request() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}

func (testCtx TestContext) Response() http.ResponseWriter {
	return httptest.NewRecorder()
}

func (testCtx TestContext) Client(clientID string) (*Client, error) {
	return nil, nil
}

func (testCtx TestContext) Deadline() (deadline time.Time, ok bool) {
	return testCtx.Context.Deadline()
}

func (testCtx TestContext) Done() <-chan struct{} {
	return testCtx.Context.Done()
}

func (testCtx TestContext) Err() error {
	return testCtx.Context.Err()
}

func (testCtx TestContext) Value(key any) any {
	return testCtx.Context.Value(key)
}

func NewTestContext(scopes Scopes) Context {
	return TestContext{
		OAuthScopes: scopes,
		Context:     context.Background(),
	}
}

func AssertTimestampWithin(t *testing.T, expected int, actual int, msgAndArgs ...any) {
	assert.Greater(t, actual, expected-10, msgAndArgs)
	assert.Less(t, actual, expected+10, msgAndArgs)
}
