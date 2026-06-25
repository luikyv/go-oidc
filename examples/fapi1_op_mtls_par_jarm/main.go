// Example fapi1_op_mtls_par_jarm demonstrates the implementation of a FAPI1 Advanced Security Profile
// OpenID Provider with mTLS authentication and PAR and JARM.
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
	clientOne, _ := authutil.ClientMTLS("client_one")
	clientTwo, _ := authutil.ClientMTLS("client_two")
	op, err := provider.New(
		provider.Config{
			Issuer:      authutil.Issuer,
			JWKSFunc:    authutil.PrivateJWKSFunc(),
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
		provider.WithProfile(goidc.ProfileFAPI1),
		provider.WithScopes(authutil.Scopes...),
		provider.WithOpenIDScopeRequired(),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithMTLS(provider.MTLSConfig{
			Host:           authutil.MTLSHost,
			ClientCertFunc: authutil.ClientCertFunc,
		}, provider.WithMTLSTokenBindingRequired()),
		provider.WithTLSAuthn(),
		provider.WithAuthCodeGrant(provider.AuthCodeGrantConfig{
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode, goidc.ResponseTypeCodeAndIDToken},
		},
			provider.WithJAR([]goidc.SignatureAlgorithm{goidc.PS256}, provider.WithJARRequired()),
			provider.WithPAR(nil, provider.WithPARRequired()),
			provider.WithClaimsParameter(),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}),
			provider.WithJARM([]goidc.SignatureAlgorithm{goidc.PS256}),
			provider.WithAuthPolicies(authutil.Policy()),
		),
		provider.WithRefreshTokenGrant(nil),
		provider.WithClaims(authutil.Claims...),
		provider.WithACRs(authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithErrorHandler(authutil.HandleError),
		provider.WithStaticClients(clientOne, clientTwo),
		provider.WithErrorRenderer(authutil.RenderError()),
		provider.WithJTIConsumer(authutil.ConsumeJTIFunc()),
		provider.WithJWTLeewayTime(30),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()
	handler = authutil.FAPIIDMiddleware(handler)

	mux.Handle("/", authutil.ClientCertMiddleware(handler))

	server := &http.Server{
		Addr:              authutil.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			ClientCAs:    authutil.ClientCACertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
			Certificates: []tls.Certificate{authutil.ServerCert()},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			MinVersion: tls.VersionTLS12,
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
