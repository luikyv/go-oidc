// Example oidc demonstrates the implementation of an Authorization Server
// that complies with the OpenID Connect specifications.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

type CtxKey string

const TenantCtxKey CtxKey = "tenant"

func main() {
	tenant1, err := provider.New(
		goidc.ProfileOpenID,
		"https://auth1.localhost",
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnSecretBasic),
		provider.WithAuthorizationCodeGrant(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError()),
	)
	if err != nil {
		log.Fatal(err)
	}

	tenant2, err := provider.New(
		goidc.ProfileOpenID,
		"https://auth2.localhost",
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnSecretPost),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.RS256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError()),
	)
	if err != nil {
		log.Fatal(err)
	}

	tenantProvider, err := provider.NewTenant(func(ctx context.Context) (*provider.Provider, error) {
		switch ctx.Value(TenantCtxKey).(string) {
		case "https://auth1.localhost":
			return tenant1, nil
		case "https://auth2.localhost":
			return tenant2, nil
		default:
			return nil, errors.New("invalid tenant")
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	mux.Handle("/", TenantMiddleware(tenantProvider.Handler()))

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

func TenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, TenantCtxKey, "https://"+r.Host)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
