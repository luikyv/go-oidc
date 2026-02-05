package provider

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultStorageMaxSize = 100

	defaultAuthnSessionTimeoutSecs  = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs      = 600
	defaultTokenLifetimeSecs        = 300
	defaultJWTLifetimeSecs          = 600
	defaultLogoutSessionTimeoutSecs = 1800 // 30 minutes.

	defaultIDTokenSigAlg       = goidc.RS256
	defaultPrivateKeyJWTSigAlg = goidc.RS256
	defaultSecretJWTSigAlg     = goidc.HS256

	defaultOpenIDFedSigAlg             = goidc.RS256
	defaultOpenIDFedTrustChainMaxDepth = 5
	defaultOpenIDFedRegType            = goidc.ClientRegistrationTypeAutomatic

	defaultSSFSigAlg = goidc.RS256

	defaultEndpointWellKnown                    = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet                = "/jwks"
	defaultEndpointPushedAuthorizationRequest   = "/par"
	defaultEndpointAuthorize                    = "/authorize"
	defaultEndpointToken                        = "/token"
	defaultEndpointUserInfo                     = "/userinfo"
	defaultEndpointDynamicClient                = "/register"
	defaultEndpointTokenIntrospection           = "/introspect"
	defaultEndpointTokenRevocation              = "/revoke"
	defaultEndpointCIBA                         = "/bc-authorize"
	defaultEndpointOpenIDFederation             = "/.well-known/openid-federation"
	defaultEndpointOpenIDFederationRegistration = "/federation/register"
	defaultEndpointEndSession                   = "/logout"
	defaultEndpointSSFJWKS                      = "/ssf/jwks"
	defaultEndpointSSFConfiguration             = "/ssf/stream"
	defaultEndpointSSFStatus                    = "/ssf/status"
	defaultEndpointSSFAddSubject                = "/ssf/subject:add"
	defaultEndpointSSFRemoveSubject             = "/ssf/subject:remove"
	defaultEndpointSSFVerification              = "/ssf/verify"
	defaultEndpointSSFPolling                   = "/ssf/poll"
)

func defaultTokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(_ context.Context, grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(goidc.DefaultOpaqueTokenLength, defaultTokenLifetimeSecs)
	}
}
