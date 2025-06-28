// Example fapi2 demonstrates the implementation of an Authorization Server
// that complies with the FAPI 2.0 specifications.
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(sourceDir, "../templates")

	clientOneJWKSFilePath := filepath.Join(sourceDir, "../keys/client_one.jwks")
	clientOneCertFilePath := filepath.Join(sourceDir, "../keys/client_one.cert")

	clientTwoJWKSFilePath := filepath.Join(sourceDir, "../keys/client_two.jwks")
	clientTwoCertFilePath := filepath.Join(sourceDir, "../keys/client_two.cert")

	serverJWKSFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.crt")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	// Create and configure the OpenID provider.
	clientOne, _ := authutil.ClientPrivateKeyJWT("client_one", clientOneJWKSFilePath)
	clientTwo, _ := authutil.ClientPrivateKeyJWT("client_two", clientTwoJWKSFilePath)
	mtlsClientOne, _ := authutil.ClientMTLS("mtls_client_one", "client_one", clientOneJWKSFilePath)
	mtlsClientTwo, _ := authutil.ClientMTLS("mtls_client_two", "client_two", clientTwoJWKSFilePath)
	op, err := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(serverJWKSFilePath),
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithPARRequired(nil, 10),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithJAR(goidc.PS256),
		provider.WithJARM(goidc.PS256),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT, goidc.ClientAuthnTLS),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken, 6000),
		provider.WithTLSCertTokenBinding(),
		provider.WithDPoP(goidc.PS256, goidc.ES256),
		provider.WithTokenBindingRequired(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy(templatesDirPath)),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithStaticClient(clientOne),
		provider.WithStaticClient(clientTwo),
		provider.WithStaticClient(mtlsClientOne),
		provider.WithStaticClient(mtlsClientTwo),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithJWTLeewayTime(30),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", handler)

	mtlsHostURL, _ := url.Parse(authutil.MTLSHost)
	mux.Handle(mtlsHostURL.Hostname()+"/", authutil.ClientCertMiddleware(handler))

	caPool := authutil.ClientCACertPool(clientOneCertFilePath, clientTwoCertFilePath)
	server := &http.Server{
		Addr:    authutil.Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:  caPool,
			ClientAuth: tls.VerifyClientCertIfGiven,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}
	if err := server.ListenAndServeTLS(
		serverCertFilePath,
		serverCertKeyFilePath,
	); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
