package goidc

import (
	"context"
	"net/http"
)

type Context interface {
	Request() *http.Request
	Response() http.ResponseWriter
	Client(clientID string) (*Client, error)
	// context.Context is embedded as a shortcut to access the request context.
	context.Context
}
