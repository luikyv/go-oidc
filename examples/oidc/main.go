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
		provider.Config{
			Issuer:      authutil.Issuer,
			JWKSFunc:    authutil.PrivateJWKSFunc(),
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.RS256, goidc.None},
		},
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserInfoSignatureAlgs(goidc.RS256, goidc.None),
		provider.WithSecretBasicAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithPrivateKeyJWTAuthn(goidc.RS256),
		provider.WithAuthCodeGrant(provider.AuthCodeGrantConfig{
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
				goidc.ResponseTypeIDToken,
				goidc.ResponseTypeToken,
				goidc.ResponseTypeCodeAndIDToken,
				goidc.ResponseTypeCodeAndToken,
				goidc.ResponseTypeIDTokenAndToken,
				goidc.ResponseTypeCodeAndIDTokenAndToken,
			},
		},
			provider.WithPAR(nil),
			provider.WithJAR(
				[]goidc.SignatureAlgorithm{goidc.RS256, goidc.None},
				provider.WithJARByReference(nil),
				provider.WithJARByReferenceUnregisteredURIs(),
			),
			provider.WithJARM([]goidc.SignatureAlgorithm{goidc.RS256}),
			provider.WithIssuerResponseParameter(),
			provider.WithClaimsParameter(),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}),
			provider.WithFormPostResponseMode(),
			provider.WithAuthPolicies(authutil.Policy()),
		),
		provider.WithRefreshTokenGrant(nil),
		provider.WithClaims(authutil.Claims...),
		provider.WithACRs(authutil.ACRs...),
		provider.WithDCR(nil,
			provider.WithDCRClientHandler(authutil.DCRFunc),
		),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithIDTokenClaims(authutil.IDTokenClaimsFunc()),
		provider.WithUserInfoClaims(authutil.UserInfoClaimsFunc()),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithErrorHandler(authutil.HandleError),
		provider.WithErrorRenderer(authutil.RenderError()),
		provider.WithDisplayValues(authutil.DisplayValues...),
		provider.WithSubjectIdentifiers(
			[]goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise},
			provider.WithPairwiseSubjectFunc(authutil.PairwiseSubjectFunc()),
		),
		provider.WithLogout(provider.LogoutConfig{
			HandleFunc: authutil.HandleLogout(),
		}, provider.WithLogoutPolicies(authutil.LogoutPolicy())),
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
