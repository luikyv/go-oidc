// Example fapiciba demonstrates the implementation of an Authorization Server
// that complies with the FAPI CIBA specification.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	op, _ := provider.New(authutil.Issuer, nil, authutil.PrivateJWKSFunc())
	_ = op.WithOptions(
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithCIBAGrant(nil, goidc.CIBADeliveryModePoll, goidc.CIBADeliveryModePing, goidc.CIBADeliveryModePush),
		provider.WithCIBAProfile(goidc.CIBAProfileFAPI),
		provider.WithRefreshTokenGrant(nil),
		provider.WithCIBAHandleSessionFunc(initBackAuthFunc()),
		provider.WithCIBAJAR(goidc.PS256),
		provider.WithMTLS(authutil.MTLSHost, authutil.ClientCertFunc),
		provider.WithTLSTokenBindingRequired(),
		provider.WithTokenAuthnMethods(goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodTLS),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithClaimsParameter(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithHandleErrorFunc(authutil.HandleError),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithDCR(nil),
		provider.WithDCRHandleClientFunc(authutil.DCRFunc),
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
		Addr:              authutil.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequestClientCert,
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

func initBackAuthFunc() goidc.HandleSessionFunc {
	return func(ctx context.Context, as *goidc.AuthnSession, c *goidc.Client) error {
		if len(as.BindingMessage) > 10 {
			return goidc.NewError(goidc.ErrorCodeInvalidBindingMessage, "invalid binding message")
		}
		return nil
	}
}

func cibaActionHandler(op *provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authReqID := r.URL.Query().Get("token")
		action := r.URL.Query().Get("type")
		if action != "allow" {
			goidcErr := goidc.NewError(goidc.ErrorCodeAccessDenied, "access denied")
			go func() {
				if err := op.DenyCIBARequest(r.Context(), authReqID, goidcErr); err != nil {
					log.Println(err)
				}
			}()
			return
		}

		as, _ := op.CIBAManager().Session(r.Context(), authReqID)
		as.Subject = as.LoginHint
		as.GrantedScopes = as.Scopes
		if as.ACRValues != "" {
			as.Store = map[string]any{"id_token_claims": map[string]any{
				goidc.ClaimACR: as.ACRValues,
			}}
		}
		_ = op.CIBAManager().SaveSession(r.Context(), as)

		go func() {
			if err := op.GrantCIBARequest(r.Context(), authReqID); err != nil {
				log.Println(err)
			}
		}()
	}
}
