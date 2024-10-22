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
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	Port             string = ":8445"
	Issuer           string = "https://auth.localhost" + Port
	MTLSHost         string = "https://matls-auth.localhost" + Port
	HeaderClientCert string = "X-Client-Cert"
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

func ClientMTLS(id, cn, jwksFilepath string) *goidc.Client {
	client := Client(id, jwksFilepath)
	client.TokenAuthnMethod = goidc.ClientAuthnTLS
	client.TLSSubDistinguishedName = "CN=" + cn

	return client
}

func ClientPrivateKeyJWT(id, jwksFilepath string) *goidc.Client {
	client := Client(id, jwksFilepath)
	client.TokenAuthnMethod = goidc.ClientAuthnPrivateKeyJWT
	return client
}

func Client(id string, jwksFilepath string) *goidc.Client {
	// Extract the public client JWKS.
	jwks := PrivateJWKS(jwksFilepath)
	var publicKeys []jose.JSONWebKey
	for _, key := range jwks.Keys {
		publicKeys = append(publicKeys, key.Public())
	}
	jwks.Keys = publicKeys
	jwksBytes, _ := json.Marshal(jwks)

	// Extract scopes IDs.
	var scopesIDs []string
	for _, scope := range Scopes {
		scopesIDs = append(scopesIDs, scope.ID)
	}

	return &goidc.Client{
		ID: id,
		ClientMetaInfo: goidc.ClientMetaInfo{
			ScopeIDs:   strings.Join(scopesIDs, " "),
			PublicJWKS: jwksBytes,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
			},
			RedirectURIs: []string{
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback",
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback?dummy1=lorem&dummy2=ipsum",
			},
		},
	}
}

func PrivateJWKS(filename string) jose.JSONWebKeySet {
	jwksFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer jwksFile.Close()

	jwksBytes, err := io.ReadAll(jwksFile)
	if err != nil {
		log.Fatal(err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		log.Fatal(err)
	}

	return jwks
}

func ClientCACertPool(clientCertFiles ...string) *x509.CertPool {

	caPool := x509.NewCertPool()

	for _, clientOneCert := range clientCertFiles {
		clientOneCert, err := os.Open(clientOneCert)
		if err != nil {
			log.Fatal(err)
		}
		defer clientOneCert.Close()

		clientCertBytes, err := io.ReadAll(clientOneCert)
		if err != nil {
			log.Fatal(err)
		}

		caPool.AppendCertsFromPEM(clientCertBytes)
	}

	return caPool
}

func DCRFunc(r *http.Request, clientInfo *goidc.ClientMetaInfo) error {
	var s []string
	for _, scope := range Scopes {
		s = append(s, scope.ID)
	}
	clientInfo.ScopeIDs = strings.Join(s, " ")

	if !slices.Contains(clientInfo.GrantTypes, goidc.GrantRefreshToken) {
		clientInfo.GrantTypes = append(clientInfo.GrantTypes, goidc.GrantRefreshToken)
	}

	return nil
}

func ValidateInitialTokenFunc(r *http.Request, s string) error {
	return nil
}

func TokenOptionsFunc(keyID string) goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(keyID, 600)
		return opts
	}
}

func ClientCertFunc(r *http.Request) (*x509.Certificate, error) {
	rawClientCert := r.Header.Get(HeaderClientCert)
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
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func ErrorLoggingFunc(r *http.Request, err error) {
	log.Printf("error during request %s: %s\n", r.RequestURI, err.Error())
}

func RenderError(templatesDir string) goidc.RenderErrorFunc {
	errorTemplate := filepath.Join(templatesDir, "/error.html")
	tmpl, err := template.ParseFiles(errorTemplate)
	if err != nil {
		log.Fatal(err)
	}

	return func(w http.ResponseWriter, r *http.Request, err error) error {
		w.WriteHeader(http.StatusOK)
		_ = tmpl.Execute(w, authnPage{
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
		clientCerts := r.TLS.PeerCertificates
		if len(clientCerts) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCerts[0].Raw,
		}
		// Convert the PEM block to a string
		pemBytes := pem.EncodeToMemory(pemBlock)

		// URL encode the PEM string
		encodedPem := url.QueryEscape(string(pemBytes))

		// Transmit the client certificate in a header.
		r.Header.Set(HeaderClientCert, encodedPem)

		next.ServeHTTP(w, r)
	})
}
