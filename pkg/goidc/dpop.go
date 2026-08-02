package goidc

import "context"

// DPoPNonceScope identifies the server role that issued a DPoP nonce. Nonces
// issued by an authorization server and a resource server are independent and
// must not be accepted across scopes.
type DPoPNonceScope string

const (
	DPoPNonceScopeAuthorizationServer DPoPNonceScope = "authorization_server"
	DPoPNonceScopeResourceServer      DPoPNonceScope = "resource_server"
)

// DPoPNonceValidation is the result of validating a server-provided DPoP nonce.
type DPoPNonceValidation struct {
	// NextNonce optionally rotates the nonce on the current successful response.
	// It must already be persisted as valid before ValidateNonce returns.
	NextNonce string
}

// DPoPNonceManager issues and validates server-provided DPoP nonces.
// Its methods may be called concurrently and implementations must be safe for
// concurrent use.
//
// IssueNonce must generate an unpredictable nonce, persist it as valid for the
// supplied scope before returning, and leave other outstanding nonces valid so
// concurrent client requests remain usable. The returned value must use the
// nonce syntax from RFC 9449 Section 8.1. Implementations are responsible for
// expiring unused nonces.
//
// ValidateNonce must return ErrNotFound for an unknown or expired nonce. RFC
// 9449 permits the same recent nonce to be accepted in multiple proofs. An
// implementation may instead enforce single-use nonces, but then validation
// and consumption must be one atomic operation so at most one concurrent call
// succeeds. Any error other than ErrNotFound is treated as an operational
// failure and fails closed.
//
// ValidateNonce may return a NextNonce to rotate the nonce in the successful
// response. The replacement must be unpredictable, use the RFC 9449 nonce
// syntax, and be persisted as valid before the method returns. Implementations
// should retain a suitable window of recent nonces for concurrent requests.
type DPoPNonceManager interface {
	IssueNonce(context.Context, DPoPNonceScope) (string, error)
	ValidateNonce(context.Context, DPoPNonceScope, string) (DPoPNonceValidation, error)
}
