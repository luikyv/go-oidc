// Package provider implements a configurable Open ID provider.
//
// A new provider can be configured with [ProviderOption] and instantiated
// using [New]. By default all sessions and clients are stored in memory.
//
// It is highly recommended to change the default storage with custom
// implementations of [goidc.ClientManager], [goidc.AuthnSessionManager] and
// [goidc.GrantSessionManager]. For more info, see [WithClientStorage],
// [WithAuthnSessionStorage] and [WithGrantSessionStorage].
//
// For authorization requests, users are authenticated with an available
// [goidc.AuthnPolicy]. The policy is responsible for interacting with the user
// and modifing the [goidc.AuthnSession] to define how access and ID tokens are
// issued and with what information.
// Check the folder examples for more details of how to set up policies.
package provider

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var _ goidc.AuthnStatus
