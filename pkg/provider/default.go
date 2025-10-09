package provider

import (
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultStorageMaxSize = 100

	defaultAuthnSessionTimeoutSecs = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs     = 600
	defaultTokenLifetimeSecs       = 300
	defaultJWTLifetimeSecs         = 600

	defaultIDTokenSigAlg       = goidc.RS256
	defaultPrivateKeyJWTSigAlg = goidc.RS256
	defaultSecretJWTSigAlg     = goidc.HS256

	defaultOpenIDFedSigAlg             = goidc.RS256
	defaultOpenIDFedTrustChainMaxDepth = 5
	defaultOpenIDFedRegType            = goidc.ClientRegistrationTypeAutomatic

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
	defaultEndpointDeviceAuthorization        = "/device_authorization"
	defaultEndpointDevice                     = "/device"
)

func defaultTokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(
			goidc.DefaultOpaqueTokenLength,
			defaultTokenLifetimeSecs,
		)
	}
}

func defaultGenerateDeviceCodeFunc() goidc.GenerateDeviceCodeFunc {
	return func() (string, error) {
		return strutil.Random(32), nil
	}
}

func defaultGenerateUserCodeFunc() goidc.GenerateUserCodeFunc {
	return func() (string, error) {
		return strutil.RandomUserCode(), nil
	}
}
