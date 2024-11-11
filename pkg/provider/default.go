package provider

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultAuthnSessionTimeoutSecs = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs     = 600
	defaultTokenLifetimeSecs       = 300
	defaultJWTLifetimeSecs         = 600
	defaultJWTLeewayTimeSecs       = 30

	defaultUserInfoSigAlg      = jose.RS256
	defaultPrivateKeyJWTSigAlg = jose.RS256
	defaultSecretJWTSigAlg     = jose.HS256

	defaultEndpointWellKnown                  = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet              = "/jwks"
	defaultEndpointPushedAuthorizationRequest = "/par"
	defaultEndpointAuthorize                  = "/authorize"
	defaultEndpointToken                      = "/token"
	defaultEndpointUserInfo                   = "/userinfo"
	defaultEndpointDynamicClient              = "/register"
	defaultEndpointTokenIntrospection         = "/introspect"
	defaultEndpointTokenRevocation            = "/revoke"
	defaultEndpointCIBA                       = "/ciba"
)

func defaultTokenOptionsFunc() goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(
			goidc.DefaultOpaqueTokenLength,
			defaultTokenLifetimeSecs,
		)
	}
}

func defaultGeneratePairwiseSubIDFunc() goidc.GeneratePairwiseSubIDFunc {
	return func(sub, sectorURI string) (string, error) {
		combined := sectorURI + "_" + sub
		hash := sha256.New()
		hash.Write([]byte(combined))
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
}
