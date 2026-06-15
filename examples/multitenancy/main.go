// Example oidc demonstrates the implementation of an Authorization Server
// that complies with the OpenID Connect specifications.
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	tenant1, err := provider.New(
		"https://auth1.localhost",
		nil,
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithSecretBasicAuthn(),
		provider.WithAuthCodeGrant(nil, goidc.ResponseTypeCode),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithErrorHandler(authutil.HandleError),
		provider.WithErrorRenderer(authutil.RenderError()),
	)
	if err != nil {
		log.Fatal(err)
	}
	tenant1Handler := tenant1.Handler()

	tenant2, err := provider.New(
		"https://auth2.localhost",
		nil,
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithSecretPostAuthn(),
		provider.WithAuthCodeGrant(nil, goidc.ResponseTypeCode),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithErrorHandler(authutil.HandleError),
		provider.WithErrorRenderer(authutil.RenderError()),
	)
	if err != nil {
		log.Fatal(err)
	}
	tenant2Handler := tenant2.Handler()

	tenantHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Host {
		case "auth1.localhost":
			tenant1Handler.ServeHTTP(w, r)
		case "auth2.localhost":
			tenant2Handler.ServeHTTP(w, r)
		default:
			http.Error(w, "invalid tenant", http.StatusNotFound)
		}
	})

	// Set up the server.
	mux := http.NewServeMux()
	mux.Handle("/", tenantHandler)

	server := &http.Server{
		Addr:              authutil.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{authutil.ServerCert()},
			MinVersion:   tls.VersionTLS12,
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
