// Example oidc demonstrates the implementation of an Authorization Server
// that complies with the OpenID Connect specifications.
package main

import (
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
	op, err := provider.New(
		goidc.ProfileOpenID,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(),
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.RS256, goidc.None),
		provider.WithUserInfoSignatureAlgs(goidc.RS256, goidc.None),
		provider.WithPAR(),
		provider.WithJAR(goidc.RS256, goidc.None),
		provider.WithJARByReference(false),
		provider.WithJARM(goidc.RS256),
		provider.WithTokenAuthnMethods(
			goidc.AuthnMethodSecretBasic,
			goidc.AuthnMethodSecretPost,
			goidc.AuthnMethodPrivateKeyJWT,
		),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.RS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithGrantTypes(goidc.GrantAuthorizationCode, goidc.GrantImplicit, goidc.GrantRefreshToken),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithACRs(authutil.ACRs[0], authutil.ACRs...),
		provider.WithDCR(),
		provider.WithDCRHandleClientFunc(authutil.DCRFunc),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicies(authutil.Policy()),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError()),
		provider.WithDisplayValues(authutil.DisplayValues[0], authutil.DisplayValues...),
		provider.WithSubIdentifierTypes(goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise),
		provider.WithPairwiseSubjectFunc(authutil.PairwiseSubjectFunc()),
		provider.WithLogout(authutil.HandleLogout(), authutil.LogoutPolicy()),
	)
	if err != nil {
		log.Fatal(err)
	}

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
