// Package ssf implements Shared Signals Framework transmitter endpoints.
// https://openid.net/specs/openid-sharedsignals-framework-1_0.html.
//
// It handles SSF discovery, stream configuration management, stream status
// management, subject management, polling and push delivery, and verification
// event scheduling. The package contains the HTTP handlers and internal
// validation/routing logic; storage, receiver authentication, signing, and
// delivery policy are provided through oidc.Configuration callbacks and
// managers.
package ssf
