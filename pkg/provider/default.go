package provider

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultStorageMaxSize = 100

	defaultAuthnSessionTimeoutSecs        = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs            = 600
	defaultTokenLifetimeSecs              = 300
	defaultJWTLifetimeSecs                = 600
	defaultLogoutSessionTimeoutSecs       = 1800 // 30 minutes.
	defaultPARLifetimeSecs                = 60   // 1 minute.
	defaultRefreshTokenLifetimeSecs       = 600
	defaultCIBADefaultSessionLifetimeSecs = 60
	defaultCIBAPollingIntervalSecs        = 5
	defaultAuthorizationCodeLifetimeSecs  = 60

	defaultAsymmetricSigAlg            = goidc.RS256
	defaultSymmetricSigAlg             = goidc.HS256
	defaultOpenIDFedTrustChainMaxDepth = 5
	defaultOpenIDFedRegType            = goidc.ClientRegistrationTypeAutomatic

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
	defaultEndpointOpenIDFederationSignedJWKS   = "/signed-jwks"
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
