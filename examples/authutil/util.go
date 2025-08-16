// Package authutil contains utilities to set up example authorization server
// using goidc.
package authutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/examples/keys"
	"github.com/luikyv/go-oidc/examples/ui"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	Port                     string = ":443"
	Issuer                   string = "https://auth.localhost"
	MTLSHost                 string = "https://matls-auth.localhost"
	headerClientCert         string = "X-Client-Cert"
	headerXFAPIInteractionID        = "X-Fapi-Interaction-Id"
)

var (
	Scopes = []goidc.Scope{
		goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeProfile,
		goidc.ScopeEmail, goidc.ScopeAddress, goidc.ScopePhone,
	}
	Claims = []string{
		goidc.ClaimEmail, goidc.ClaimEmailVerified, goidc.ClaimPhoneNumber,
		goidc.ClaimPhoneNumberVerified, goidc.ClaimAddress,
	}
	ACRs          = []goidc.ACR{goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver}
	DisplayValues = []goidc.DisplayValue{goidc.DisplayValuePage, goidc.DisplayValuePopUp}
)

func ClientMTLS(id string) (*goidc.Client, goidc.JSONWebKeySet) {
	client, jwks := Client(id)
	client.TokenAuthnMethod = goidc.ClientAuthnTLS
	client.TLSSubDistinguishedName = "CN=" + id

	return client, jwks
}

func ClientPrivateKeyJWT(id string) (*goidc.Client, goidc.JSONWebKeySet) {
	client, jwks := Client(id)
	client.TokenAuthnMethod = goidc.ClientAuthnPrivateKeyJWT
	return client, jwks
}

func Client(id string) (*goidc.Client, goidc.JSONWebKeySet) {
	// Extract the public client JWKS.
	jwks := privateJWKS(id)

	// Extract scopes IDs.
	scopesIDs := make([]string, len(Scopes))
	for i, scope := range Scopes {
		scopesIDs[i] = scope.ID
	}

	publicJWKS := jwks.Public()
	return &goidc.Client{
		ID: id,
		ClientMeta: goidc.ClientMeta{
			ScopeIDs:   strings.Join(scopesIDs, " "),
			PublicJWKS: &publicJWKS,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
				goidc.GrantImplicit,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
				goidc.ResponseTypeCodeAndIDToken,
			},
			RedirectURIs: []string{
				"http://localhost/callback",
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback",
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback?dummy1=lorem&dummy2=ipsum",
			},
		},
	}, jwks
}

func PrivateJWKSFunc() goidc.JWKSFunc {
	jwksBytes, err := keys.FS.ReadFile("server.jwks")
	if err != nil {
		log.Fatal(err)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		log.Fatal(err)
	}

	return func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return jwks, nil
	}
}

func privateJWKS(clientID string) goidc.JSONWebKeySet {
	jwksBytes, err := keys.FS.ReadFile(clientID + ".jwks")
	if err != nil {
		log.Fatal(err)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		log.Fatal(err)
	}

	return jwks
}

func ServerCert() tls.Certificate {
	certBytes, err := keys.FS.ReadFile("server.crt")
	if err != nil {
		log.Fatal(err)
	}

	keyBytes, err := keys.FS.ReadFile("server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		log.Fatal(err)
	}

	return tlsCert
}

func ClientCACertPool() *x509.CertPool {

	caPool := x509.NewCertPool()

	clientOneCert, err := keys.FS.ReadFile("client_one.crt")
	if err != nil {
		log.Fatal(err)
	}
	caPool.AppendCertsFromPEM(clientOneCert)

	clientTwoCert, err := keys.FS.ReadFile("client_two.crt")
	if err != nil {
		log.Fatal(err)
	}
	caPool.AppendCertsFromPEM(clientTwoCert)

	return caPool
}

func DCRFunc(r *http.Request, _ string, meta *goidc.ClientMeta) error {
	s := make([]string, len(Scopes))
	for i, scope := range Scopes {
		s[i] = scope.ID
	}
	meta.ScopeIDs = strings.Join(s, " ")

	if !slices.Contains(meta.GrantTypes, goidc.GrantRefreshToken) {
		meta.GrantTypes = append(meta.GrantTypes, goidc.GrantRefreshToken)
	}

	return nil
}

func ValidateInitialTokenFunc(r *http.Request, s string) error {
	return nil
}

func TokenOptionsFunc(alg goidc.SignatureAlgorithm) goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(alg, 600)
		return opts
	}
}

func ClientCertFunc(r *http.Request) (*x509.Certificate, error) {
	rawClientCert := r.Header.Get(headerClientCert)
	if rawClientCert == "" {
		return nil, errors.New("the client certificate was not informed")
	}

	// Apply URL decoding.
	rawClientCert, err := url.QueryUnescape(rawClientCert)
	if err != nil {
		return nil, fmt.Errorf("could not url decode the client certificate: %w", err)
	}

	clientCertPEM, _ := pem.Decode([]byte(rawClientCert))
	if clientCertPEM == nil {
		return nil, errors.New("could not decode the client certificate")
	}

	clientCert, err := x509.ParseCertificate(clientCertPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse the client certificate: %w", err)
	}

	return clientCert, nil
}

func IssueRefreshToken(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
	return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken)
}

func HTTPClient(_ context.Context) *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func ErrorLoggingFunc(ctx context.Context, err error) {
	log.Printf("error: %s\n", err.Error())
}

func RenderError() goidc.RenderErrorFunc {
	tmpl := template.Must(template.ParseFS(ui.FS, "*.html"))
	return func(w http.ResponseWriter, r *http.Request, err error) error {
		w.WriteHeader(http.StatusOK)
		_ = tmpl.ExecuteTemplate(w, "error.html", authnPage{
			Error: err.Error(),
		})
		return nil
	}

}

func CheckJTIFunc() goidc.CheckJTIFunc {
	jtiStore := make(map[string]struct{})
	return func(ctx context.Context, jti string) error {
		if _, ok := jtiStore[jti]; ok {
			return errors.New("jti already used")
		}

		jtiStore[jti] = struct{}{}
		return nil
	}
}

func ClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: r.TLS.PeerCertificates[0].Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)

		encodedPem := url.QueryEscape(string(pemBytes))
		r.Header.Set(headerClientCert, encodedPem)

		next.ServeHTTP(w, r)
	})
}

func FAPIIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionID := r.Header.Get(headerXFAPIInteractionID)

		// Verify if the interaction ID is valid, generate a new value if not.
		if _, err := uuid.Parse(interactionID); err != nil {
			interactionID = uuid.NewString()
		}

		// Return the same interaction ID in the response or a new valid value
		// if the original is invalid.
		w.Header().Add(headerXFAPIInteractionID, interactionID)

		next.ServeHTTP(w, r)
	})
}
