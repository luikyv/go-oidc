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

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	serverJWKSFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.crt")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	// Create and configure the OpenID provider.
	op, _ := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(serverJWKSFilePath),
	)
	_ = op.WithOptions(
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithCIBAGrant(initBackAuthFunc(), validateBackAuthFunc(),
			goidc.CIBATokenDeliveryModePoll, goidc.CIBATokenDeliveryModePing, goidc.CIBATokenDeliveryModePush),
		provider.WithCIBAJAR(goidc.PS256),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithTLSCertTokenBindingRequired(),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT, goidc.ClientAuthnTLS),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithClaimsParameter(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken, 6000),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithDCR(authutil.DCRFunc, authutil.ValidateInitialTokenFunc),
	)

	// Set up the server.
	mux := http.NewServeMux()
	handler := op.Handler()
	handler = authutil.FAPIIDMiddleware(handler)

	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", handler)
	mux.Handle(hostURL.Hostname()+"/ciba-action", cibaActionHandler(op))

	mtlsHostURL, _ := url.Parse(authutil.MTLSHost)
	handler = authutil.ClientCertMiddleware(handler)
	mux.Handle(mtlsHostURL.Hostname()+"/", handler)

	server := &http.Server{
		Addr:    authutil.Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
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

		if len(as.BindingMessage) > 10 {
			return goidc.NewError(goidc.ErrorCodeInvalidBindingMessage,
				"invalid binding message")
		}

		as.SetUserID(as.LoginHint)
		as.StoreParameter("ready", false)
		as.GrantScopes(as.Scopes)

		if as.RequestedExpiry != nil {
			as.ExpiresAtTimestamp = timeutil.TimestampNow() + *as.RequestedExpiry
		}

		if as.ACRValues != "" {
			as.SetIDTokenClaim(goidc.ClaimACR, as.ACRValues)
		}

		return nil
	}
}

func validateBackAuthFunc() goidc.ValidateBackAuthFunc {
	return func(ctx context.Context, as *goidc.AuthnSession) error {
		if as.StoredParameter("error") == true {
			return goidc.NewError(goidc.ErrorCodeAccessDenied,
				"access denied").WithStatusCode(http.StatusBadRequest)
		}

		if as.StoredParameter("ready") != true {
			return goidc.NewError(goidc.ErrorCodeAuthPending, "not ready")
		}

		return nil
	}
}

func cibaActionHandler(op *provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authReqID := r.URL.Query().Get("token")
		authnSession, _ := op.AuthnSessionByCIBAAuthID(r.Context(), authReqID)

		action := r.URL.Query().Get("type")
		if action != "allow" {
			authnSession.StoreParameter("error", true)
			_ = op.SaveAuthnSession(r.Context(), authnSession)
			goidcErr := goidc.NewError(goidc.ErrorCodeAccessDenied, "access denied")
			go func() {
				if err := op.NotifyCIBAFailure(r.Context(), authReqID, goidcErr); err != nil {
					log.Println(err)
				}
			}()
			return
		}

		authnSession.StoreParameter("ready", true)
		_ = op.SaveAuthnSession(r.Context(), authnSession)
		go func() {
			if err := op.NotifyCIBASuccess(r.Context(), authReqID); err != nil {
				log.Println(err)
			}
		}()
	}
}
