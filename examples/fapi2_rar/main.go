// Example fapi2_rar demonstrates the implementation of a FAPI2 Security Profile
// OpenID Provider with rich authorization requests.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	clientOne, _ := authutil.ClientPrivateKeyJWT("client_one")
	clientTwo, _ := authutil.ClientPrivateKeyJWT("client_two")
	op, err := provider.New(
		goidc.ProfileFAPI2,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithPARRequired(),
		provider.WithTokenAuthnMethods(goidc.AuthnMethodPrivateKeyJWT),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithDPoPRequired(goidc.PS256, goidc.ES256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithRefreshTokenGrant(),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.PS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithStaticClients(clientOne, clientTwo),
		provider.WithRenderErrorFunc(authutil.RenderError()),
		provider.WithCheckJTIFunc(authutil.CheckJTIFunc()),
		provider.WithJWTLeewayTime(30),
		provider.WithRAR("customer_information"),
		provider.WithRARCompareDetailsFunc(func(_ context.Context, granted, requested []goidc.AuthDetail) error {
			grantedDetailTypes := make([]goidc.AuthDetailType, len(granted))
			for i, grantedDetail := range granted {
				grantedDetailTypes[i] = grantedDetail.Type()
			}

			for _, requestedDetail := range requested {
				if !slices.Contains(grantedDetailTypes, requestedDetail.Type()) {
					return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "authorization details do not match")
				}
			}
			return nil
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", op.Handler())

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
