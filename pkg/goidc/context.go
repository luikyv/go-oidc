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
