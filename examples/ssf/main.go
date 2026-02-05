package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	manager := storage.NewSSFManager(100)
	scope := goidc.NewScope("ssf.events")
	client := &goidc.Client{
		ID:           "test_client",
		HashedSecret: hashutil.BCryptHash("test_secret"),
		ClientMeta: goidc.ClientMeta{
			ScopeIDs:         scope.ID,
			TokenAuthnMethod: goidc.ClientAuthnSecretPost,
			GrantTypes: []goidc.GrantType{
				goidc.GrantClientCredentials,
			},
		},
	}

	op, _ := provider.New(goidc.ProfileOpenID, authutil.Issuer, authutil.PrivateJWKSFunc())
	_ = op.WithOptions(
		provider.WithScopes(scope),
		provider.WithClientCredentialsGrant(),
		provider.WithStaticClient(client),
		provider.WithSSF(authutil.PrivateJWKSFunc()),
		provider.WithSSFEventStreamManager(manager),
		provider.WithSSFDeliveryMethods(goidc.SSFDeliveryMethodPoll, goidc.SSFDeliveryMethodPush),
		provider.WithSSFEventPollManager(manager),
		provider.WithSSFEventStreamStatusManagement(),
		provider.WithSSFEventStreamSubjectManagement(),
		provider.WithSSFEventStreamSubjectManager(manager),
		provider.WithSSFStreamVerification(),
		provider.WithSSFEventStreamVerificationManager(manager),
		provider.WithSSFDefaultSubjects(goidc.SSFDefaultSubjectNone),
		provider.WithSSFAuthorizationSchemes(goidc.SSFAuthorizationScheme{SpecVersion: "urn:ietf:rfc:6749"}),
		provider.WithSSFAuthenticatedReceiverFunc(func(r *http.Request) (goidc.SSFReceiver, error) {
			tokenInfo, err := op.TokenInfoFromRequest(r)
			if err != nil {
				return goidc.SSFReceiver{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid token")
			}
			return goidc.SSFReceiver{
				ID: tokenInfo.ClientID,
				EventsSupported: []goidc.SSFEventType{
					goidc.SSFEventTypeCAEPCredentialChange,
					goidc.SSFEventTypeCAEPSessionRevoked,
				},
			}, nil
		}),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithSSFHTTPClientFunc(authutil.HTTPClient),
	)

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Publish verification events.
				for streamID, opts := range manager.StreamVerifications {
					if err := op.PublishSSFEvent(ctx, streamID, goidc.NewSSFVerificationEvent(streamID, opts)); err != nil {
						log.Println(err)
					} else {
						delete(manager.StreamVerifications, streamID)
					}
				}

				// Publish delivered events.
				for streamID, stream := range manager.Streams {
					for _, eventType := range stream.EventsDelivered {
						for _, sub := range manager.StreamSubjects[streamID] {
							if err := op.PublishSSFEvent(ctx, streamID, goidc.SSFEvent{
								Type:    eventType,
								Subject: sub,
							}); err != nil {
								log.Println(err)
							}
						}
					}
				}
			}
		}
	}()
	defer cancel()
	defer ticker.Stop()

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

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
