package provider

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultAuthnSessionTimeoutSecs = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs     = 600
	defaultTokenLifetimeSecs       = 300
	defaultAssertionLifetimeSecs   = 600

	defaultEndpointWellKnown                  = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet              = "/jwks"
	defaultEndpointPushedAuthorizationRequest = "/par"
	defaultEndpointAuthorize                  = "/authorize"
	defaultEndpointToken                      = "/token"
	defaultEndpointUserInfo                   = "/userinfo"
	defaultEndpointDynamicClient              = "/register"
	defaultEndpointTokenIntrospection         = "/introspect"
)

func defaultTokenOptionsFunc(
	sigKeyID string,
) goidc.TokenOptionsFunc {
	return func(c *goidc.Client, scopes string) (goidc.TokenOptions, error) {
		return goidc.NewJWTTokenOptions(
			sigKeyID,
			defaultTokenLifetimeSecs,
		), nil
	}
}

func defaultClientCertFunc() goidc.ClientCertFunc {
	return func(r *http.Request) (*x509.Certificate, bool) {
		rawClientCert := r.Header.Get(goidc.HeaderClientCertificate)
		if rawClientCert != "" {
			return nil, false
		}

		rawClientCertDecoded, err := url.QueryUnescape(rawClientCert)
		if err != nil {
			return nil, false
		}

		clientCertPEM, _ := pem.Decode([]byte(rawClientCertDecoded))
		if clientCertPEM == nil {
			return nil, false
		}

		clientCert, err := x509.ParseCertificate(clientCertPEM.Bytes)
		if err != nil {
			return nil, false
		}

		return clientCert, true
	}
}
