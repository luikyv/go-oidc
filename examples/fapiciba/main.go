// Example fapiciba demonstrates the implementation of an Authorization Server
// that complies with the FAPI CIBA specification.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var openidProvider provider.Provider

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	serverJWKSFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "ps256_key"

	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(serverJWKSFilePath),
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserSignatureAlgs(jose.PS256),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT, goidc.ClientAuthnTLS),
		provider.WithPrivateKeyJWTSignatureAlgs(jose.PS256),
		provider.WithClaimsParameter(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken, 6000),
		provider.WithTLSCertTokenBinding(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(serverKeyID)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithDCR(authutil.DCRFunc, authutil.ValidateInitialTokenFunc),
		provider.WithCIBAGrant(initBackAuthFunc(), validateBackAuthFunc(),
			goidc.CIBATokenDeliveryModePoll, goidc.CIBATokenDeliveryModePing, goidc.CIBATokenDeliveryModePush),
		provider.WithCIBAJAR(jose.PS256),
	)
	if err != nil {
		log.Fatal(err)
	}
	openidProvider = op

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()

	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", handler)

	mtlsHostURL, _ := url.Parse(authutil.MTLSHost)
	mux.Handle(mtlsHostURL.Hostname()+"/", authutil.ClientCertMiddleware(handler))

	server := &http.Server{
		Addr:    authutil.Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.NoClientCert,
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

func initBackAuthFunc() goidc.InitBackAuthFunc {
	return func(ctx context.Context, as *goidc.AuthnSession) error {

		as.SetUserID(as.LoginHint)
		as.StoreParameter("ready", false)

		if as.ACRValues != "" {
			as.SetIDTokenClaim(goidc.ClaimACR, as.ACRValues)
		}

		go func() {
			time.Sleep(10 * time.Second)
			as.GrantScopes(as.Scopes)
			as.StoreParameter("ready", true)
			if err := openidProvider.NotifyAuth(ctx, as.PushedAuthReqID); err != nil {
				log.Println(err)
			}
		}()
		return nil
	}
}

func validateBackAuthFunc() goidc.ValidateBackAuthFunc {
	return func(ctx context.Context, as *goidc.AuthnSession) error {
		if as.Parameter("ready") == true {
			return nil
		}
		return goidc.NewError(goidc.ErrorCodeAuthPending, "not ready")
	}
}
