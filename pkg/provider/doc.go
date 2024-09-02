// Package provider implements a customizable Open ID provider.
//
// A new provider can be configured with [ProviderOption]s and instantiated
// using [New]. By default all sessions and clients are stored in memory.
//
// It is highly recommended to change the default storage with custom
// implementations of [goidc.ClientManager], [goidc.AuthnSessionManager] and
// [goidc.GrantSessionManager]. For more info, see [WithStorage].
package provider

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var _ goidc.Profile
