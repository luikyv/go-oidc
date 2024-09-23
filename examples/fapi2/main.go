package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	port     string = ":8445"
	issuer   string = "https://auth.localhost" + port
	mtlsHost string = "https://matls-auth.localhost" + port
)

var (
	scopes = []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeEmail}
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	clientOneJWKSFilePath := filepath.Join(sourceDir, "../keys/client_one.jwks")
	clientOneCertFilePath := filepath.Join(sourceDir, "../keys/client_one.cert")

	clientTwoJWKSFilePath := filepath.Join(sourceDir, "../keys/client_two.jwks")
	clientTwoCertFilePath := filepath.Join(sourceDir, "../keys/client_two.cert")

	jwksFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	certFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	certKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "ps256_key"

	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileFAPI2,
		issuer,
		privateJWKS(jwksFilePath),
		provider.WithScopes(scopes...),
		provider.WithUserInfoSignatureKeyIDs(serverKeyID),
		provider.WithPARRequired(),
		provider.WithUnregisteredRedirectURIsForPAR(),
		provider.WithRedirectURIRequiredForPAR(),
		provider.WithMTLS(mtlsHost),
		provider.WithJAR(jose.PS256),
		provider.WithJARM(serverKeyID),
		provider.WithTLSAuthn(),
		provider.WithPrivateKeyJWTAuthn(jose.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithRefreshTokenGrant(),
		provider.WithShouldIssueRefreshTokenFunc(issueRefreshToken),
		provider.WithRefreshTokenLifetimeSecs(6000),
		provider.WithTLSCertTokenBinding(),
		provider.WithDPoP(jose.PS256, jose.ES256),
		provider.WithTokenBindingRequired(),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(dcrPlugin(scopes)),
		provider.WithTokenOptions(tokenOptions(serverKeyID)),
		provider.WithHTTPClientFunc(httpClient),
		provider.WithPolicy(policy()),
		provider.WithHandleErrorFunc(func(r *http.Request, err error) {
			log.Printf("error during request %s: %s\n", r.RequestURI, err.Error())
		}),
		provider.WithStaticClient(clientPrivateKeyJWT("client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(clientPrivateKeyJWT("client_two", clientTwoJWKSFilePath)),
		provider.WithStaticClient(clientMTLS("mtls_client_one", "client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(clientMTLS("mtls_client_two", "client_two", clientTwoJWKSFilePath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	caPool := clientCACertPool(clientOneCertFilePath, clientTwoCertFilePath)
	tlsOpts := provider.TLSOptions{
		TLSAddress: port,
		ServerCert: certFilePath,
		ServerKey:  certKeyFilePath,
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

func clientMTLS(id, cn, jwksFilepath string) *goidc.Client {
	client := client(id, jwksFilepath)
	client.AuthnMethod = goidc.ClientAuthnTLS
	client.TLSSubDistinguishedName = "CN=" + cn

	return client
}

func clientPrivateKeyJWT(id, jwksFilepath string) *goidc.Client {
	client := client(id, jwksFilepath)
	client.AuthnMethod = goidc.ClientAuthnPrivateKeyJWT
	return client
}

func client(id string, jwksFilepath string) *goidc.Client {
	// Extract the public client JWKS.
	jwks := privateJWKS(jwksFilepath)
	var publicKeys []jose.JSONWebKey
	for _, key := range jwks.Keys {
		publicKeys = append(publicKeys, key.Public())
	}
	jwks.Keys = publicKeys
	jwksBytes, _ := json.Marshal(jwks)

	// Extract scopes IDs.
	var scopesIDs []string
	for _, scope := range scopes {
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
		},
	}
}

func policy() goidc.AuthnPolicy {
	return goidc.NewPolicy(
		"policy",
		func(r *http.Request, client *goidc.Client, session *goidc.AuthnSession) bool { return true },
		authenticateUser,
	)
}

func dcrPlugin(scopes []goidc.Scope) goidc.HandleDynamicClientFunc {
	return func(r *http.Request, clientInfo *goidc.ClientMetaInfo) error {
		var s []string
		for _, scope := range scopes {
			s = append(s, scope.ID)
		}
		clientInfo.ScopeIDs = strings.Join(s, " ")

		if !slices.Contains(clientInfo.GrantTypes, goidc.GrantRefreshToken) {
			clientInfo.GrantTypes = append(clientInfo.GrantTypes, goidc.GrantRefreshToken)
		}

		return nil
	}
}

func tokenOptions(keyID string) goidc.TokenOptionsFunc {
	return func(client *goidc.Client, grantInfo goidc.GrantInfo) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(keyID, 600)
		return opts
	}
}

func issueRefreshToken(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
	return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken)
}

func httpClient(_ *http.Request) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func clientCACertPool(clientOneCertFile, clientTwoCertFile string) *x509.CertPool {
	clientOneCert, err := os.Open(clientOneCertFile)
	if err != nil {
		log.Fatal(err)
	}
	defer clientOneCert.Close()

	clientOneCertBytes, err := io.ReadAll(clientOneCert)
	if err != nil {
		log.Fatal(err)
	}

	clientTwoCert, err := os.Open(clientTwoCertFile)
	if err != nil {
		log.Fatal(err)
	}
	defer clientTwoCert.Close()

	clientTwoCertBytes, err := io.ReadAll(clientTwoCert)
	if err != nil {
		log.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(clientOneCertBytes)
	caPool.AppendCertsFromPEM(clientTwoCertBytes)

	return caPool
}

func privateJWKS(filename string) jose.JSONWebKeySet {
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

func authenticateUser(
	w http.ResponseWriter,
	r *http.Request,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.SetUserID("random@gmail.com")
	session.GrantScopes(session.Scopes)
	session.SetIDTokenClaimAuthTime(timeutil.TimestampNow())

	// Add claims based on the claims parameter.
	if session.Claims != nil {

		// acr claim.
		acrClaim, ok := session.Claims.IDToken[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}
		acrClaim, ok = session.Claims.UserInfo[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}

		// email claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmail]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimEmail, "random@gmail.com")
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmail]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmailVerified]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimEmailVerified, true)
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmailVerified]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, goidc.ScopeEmail.ID) {
		session.SetUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		session.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
	}

	return goidc.StatusSuccess
}
