// Package storage provides the default implementations of the storage
// interfaces [goidc.ClientManager], [goidc.AuthnSessionManager] and
// [goidc.GrantSessionManager].
//
// The implementations store entities in memory so when the server restarts all
// of them are lost.
package storage
