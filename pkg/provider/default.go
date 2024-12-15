package provider

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultAuthnSessionTimeoutSecs = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs     = 600
	defaultTokenLifetimeSecs       = 300
	defaultJWTLifetimeSecs         = 600

	defaultIDTokenSigAlg       = goidc.RS256
	defaultPrivateKeyJWTSigAlg = goidc.RS256
	defaultSecretJWTSigAlg     = goidc.HS256

	defaultOpenIDFedStatementSigAlg    = goidc.RS256
	defaultOpenIDFedTrustChainMaxDepth = 5

	defaultEndpointWellKnown                  = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet              = "/jwks"
	defaultEndpointPushedAuthorizationRequest = "/par"
	defaultEndpointAuthorize                  = "/authorize"
	defaultEndpointToken                      = "/token"
	defaultEndpointUserInfo                   = "/userinfo"
	defaultEndpointDynamicClient              = "/register"
	defaultEndpointTokenIntrospection         = "/introspect"
	defaultEndpointTokenRevocation            = "/revoke"
	defaultEndpointCIBA                       = "/bc-authorize"
	defaultEndpointOpenIDFederation           = "/.well-known/openid-federation"
)

func defaultTokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(
			goidc.DefaultOpaqueTokenLength,
			defaultTokenLifetimeSecs,
		)
	}
}
