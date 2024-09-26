// Package authorize handles the implementation of endpoints for authorization
// requests and pushed authorization requests.
//
// In terms of parameter validation, the redirect URI must ALWAYS be validated
// first.
// This ensures that any subsequent errors can be properly redirected to the
// client.
package authorize
