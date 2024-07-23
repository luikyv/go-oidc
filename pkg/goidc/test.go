package goidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestContext struct {
	OAuthScopes Scopes
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

func NewTestContext(scopes Scopes) Context {
	return TestContext{
		OAuthScopes: scopes,
	}
}

func AssertTimestampWithin(t *testing.T, expected int, actual int, msgAndArgs ...any) {
	assert.Greater(t, actual, expected-10, msgAndArgs)
	assert.Less(t, actual, expected+10, msgAndArgs)
}
