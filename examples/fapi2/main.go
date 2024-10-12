package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-jose/go-jose/v4"
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
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "ps256_key"

	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKS(serverJWKSFilePath),
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserInfoSignatureKeyIDs(serverKeyID),
		provider.WithPARRequired(),
		provider.WithPARLifetime(10),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithJAR(jose.PS256),
		provider.WithJARM(serverKeyID),
		provider.WithTokenAuthnMethods(
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnTLS,
		),
		provider.WithPrivateKeyJWTSignatureAlgs(jose.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken),
		provider.WithRefreshTokenLifetime(6000),
		provider.WithTLSCertTokenBinding(),
		provider.WithDPoP(jose.PS256, jose.ES256),
		provider.WithTokenBindingRequired(),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs[1:]...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(serverKeyID)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(authutil.Policy(templatesDirPath)),
		provider.WithHandleErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithStaticClient(authutil.ClientPrivateKeyJWT("client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientPrivateKeyJWT("client_two", clientTwoJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientMTLS("mtls_client_one", "client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientMTLS("mtls_client_two", "client_two", clientTwoJWKSFilePath)),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

	hostURL, _ := url.Parse(authutil.Issuer)
	// Remove the port from the host name if any.
	host := strings.Split(hostURL.Host, ":")[0]
	mux.Handle(host+"/", handler)

	mtlsHostURL, _ := url.Parse(authutil.MTLSHost)
	// Remove the port from the host name if any.
	mtlsHost := strings.Split(mtlsHostURL.Host, ":")[0]
	mux.Handle(mtlsHost+"/", authutil.ClientCertMiddleware(handler))

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
	if err := server.ListenAndServeTLS(serverCertFilePath, serverCertKeyFilePath); err != nil {
		log.Fatal(err)
	}
}
