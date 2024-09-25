package main

import (
	"crypto/tls"
	"log"
	"path/filepath"
	"runtime"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

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
		provider.WithPARLifetimeSecs(10),
		provider.WithUnregisteredRedirectURIsForPAR(),
		provider.WithMTLS(authutil.MTLSHost),
		provider.WithJAR(jose.PS256),
		provider.WithJARM(serverKeyID),
		provider.WithTLSAuthn(),
		provider.WithPrivateKeyJWTAuthn(jose.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithRefreshTokenGrant(),
		provider.WithShouldIssueRefreshTokenFunc(authutil.IssueRefreshToken),
		provider.WithRefreshTokenLifetimeSecs(6000),
		provider.WithTLSCertTokenBinding(),
		provider.WithDPoP(jose.PS256, jose.ES256),
		provider.WithTokenBindingRequired(),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(authutil.ACRs...),
		provider.WithDCR(authutil.DCRFunc),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(serverKeyID)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(authutil.Policy()),
		provider.WithHandleErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithStaticClient(authutil.ClientPrivateKeyJWT("client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientPrivateKeyJWT("client_two", clientTwoJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientMTLS("mtls_client_one", "client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(authutil.ClientMTLS("mtls_client_two", "client_two", clientTwoJWKSFilePath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	caPool := authutil.ClientCACertPool(clientOneCertFilePath, clientTwoCertFilePath)
	tlsOpts := provider.TLSOptions{
		TLSAddress: authutil.Port,
		ServerCert: serverCertFilePath,
		ServerKey:  serverCertKeyFilePath,
		CaCertPool: caPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	if err := op.RunTLS(tlsOpts, goidc.ClientCertMiddleware); err != nil {
		log.Fatal(err)
	}
}
