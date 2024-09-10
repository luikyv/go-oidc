package provider

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	defaultAuthnSessionTimeoutSecs  = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs      = 600
	defaultTokenLifetimeSecs        = 300
	defaultRefreshTokenLifetimeSecs = 3600 // 1 hour.
	defaultPARLifetimeSecs          = 60
	defaultJWTLifetimeSecs          = 600

	defaultEndpointWellKnown                  = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet              = "/jwks"
	defaultEndpointPushedAuthorizationRequest = "/par"
	defaultEndpointAuthorize                  = "/authorize"
	defaultEndpointToken                      = "/token"
	defaultEndpointUserInfo                   = "/userinfo"
	defaultEndpointDynamicClient              = "/register"
	defaultEndpointTokenIntrospection         = "/introspect"
)

func defaultIssueRefreshTokenFunc() goidc.IssueRefreshTokenFunc {
	return func(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
		return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) &&
			strutil.ContainsOfflineAccess(grantInfo.GrantedScopes)
	}
}

func defaultTokenOptionsFunc(
	sigKeyID string,
) goidc.TokenOptionsFunc {
	return func(c *goidc.Client, grantInfo goidc.GrantInfo) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(
			sigKeyID,
			defaultTokenLifetimeSecs,
		)
	}
}

// defaultClientCertFunc returns a function that extracts a client certificate
// from the request.
// It looks for a certificate in the header [goidc.HeaderClientCert].
// The certificate is expected to be a URL encoded PEM certificate.
func defaultClientCertFunc() goidc.ClientCertFunc {
	return func(r *http.Request) (*x509.Certificate, error) {
		rawClientCert := r.Header.Get(goidc.HeaderClientCert)
		if rawClientCert == "" {
			return nil, errors.New("the client certificate was not informed")
		}

		// Apply URL decoding.
		rawClientCert, err := url.QueryUnescape(rawClientCert)
		if err != nil {
			return nil, fmt.Errorf("could not url decode the client certificate: %w", err)
		}

		clientCertPEM, _ := pem.Decode([]byte(rawClientCert))
		if clientCertPEM == nil {
			return nil, errors.New("could not decode the client certificate")
		}

		clientCert, err := x509.ParseCertificate(clientCertPEM.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse the client certificate: %w", err)
		}

		return clientCert, nil
	}
}
