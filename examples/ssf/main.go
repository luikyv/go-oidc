// Example ssf demonstrates the implementation of an Authorization Server
// that supports Shared Signals Framework (SSF) for security event transmission.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	ctxKeyClientID = "client_id"
)

func main() {
	scope := goidc.NewScope("ssf.events")
	client := authutil.ClientSecretPost("client_one", "ssf_secret", scope)

	op, _ := provider.New(goidc.ProfileOpenID, authutil.Issuer, authutil.PrivateJWKSFunc())
	_ = op.WithOptions(
		provider.WithScopes(scope),
		provider.WithClientCredentialsGrant(),
		provider.WithStaticClient(client),
		provider.WithSSF(authutil.PrivateJWKSFunc(), func(ctx context.Context) (goidc.SSFReceiver, error) {
			clientID := ctx.Value(ctxKeyClientID).(string)
			if clientID == "" {
				return goidc.SSFReceiver{}, errors.New("client id is required")
			}
			return goidc.SSFReceiver{ID: clientID}, nil
		}),
		provider.WithSSFEventTypes(goidc.SSFEventTypeCAEPCredentialChange, goidc.SSFEventTypeCAEPSessionRevoked),
		provider.WithSSFSignatureAlgorithm(goidc.RS256),
		provider.WithSSFDeliveryMethods(goidc.SSFDeliveryMethodPoll, goidc.SSFDeliveryMethodPush),
		provider.WithSSFEventStreamStatusManagement(),
		provider.WithSSFEventStreamSubjectManagement(),
		provider.WithSSFEventStreamVerification(),
		provider.WithSSFMinVerificationInterval(5),
		provider.WithSSFDefaultSubjects(goidc.SSFDefaultSubjectAll),
		provider.WithSSFAuthorizationSchemes(goidc.SSFAuthorizationScheme{SpecificationURN: "urn:ietf:rfc:6749"}),
		provider.WithSSFInactivityTimeoutSecs(30, func(ctx context.Context, stream *goidc.SSFEventStream) error {
			stream.Status = goidc.SSFEventStreamStatusPaused
			stream.StatusReason = "stream has expired"
			return nil
		}),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithSSFHTTPClientFunc(authutil.HTTPClient),
	)

	// Set up the server.
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/ssf") || r.URL.Path == "/ssf/jwks" {
				next.ServeHTTP(w, r)
				return
			}

			_, tokenInfo, err := op.TokenInfoFromRequest(r)
			if err != nil {
				log.Printf("error getting token info: %v", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientID, tokenInfo.ClientID))
			next.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	handler := op.Handler(middleware)

	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", handler)

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
