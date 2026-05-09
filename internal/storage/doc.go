// Package storage provides the default in-memory implementation of the storage
// interfaces defined in [goidc], including [goidc.Manager], [goidc.AuthCodeManager],
// [goidc.RefreshTokenManager], [goidc.PARManager], [goidc.CIBAManager], and
// [goidc.DeviceGrantManager].
//
// All entities are stored in memory, so they are lost when the server restarts.
package storage
