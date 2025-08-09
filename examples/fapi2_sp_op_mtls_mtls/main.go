// Example fapi2_sp_op_mtls_mtls demonstrates the implementation of a FAPI2 Security Profile
// OpenID Provider with mTLS authentication and sender constrained tokens using TLS certificates.
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	clientOne, _ := authutil.ClientMTLS("client_one")
	clientTwo, _ := authutil.ClientMTLS("client_two")
	op, err := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithPARRequired(nil, 10),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithTLSCertTokenBindingRequired(),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnTLS),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken, 6000),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithStaticClient(clientOne),
		provider.WithStaticClient(clientTwo),
		provider.WithRenderErrorFunc(authutil.RenderError()),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithJWTLeewayTime(30),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", authutil.ClientCertMiddleware(op.Handler()))

	server := &http.Server{
		Addr:    authutil.Port,
		Handler: mux,
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
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
