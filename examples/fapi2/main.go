package main

import (
	"crypto/tls"
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
	port   string = ":8445"
	issuer string = "https://auth.localhost" + port
)

var (
	scopes = []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeEmail}
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)
	clientOneJWKSFilePath := filepath.Join(sourceDir, "../keys/client_one.jwks")
	clientTwoJWKSFilePath := filepath.Join(sourceDir, "../keys/client_two.jwks")
	jwksFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	certFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	certKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "ps256_key"

	// Create and configure the OpenID provider.
	op, err := provider.New(
		issuer,
		privateJWKS(jwksFilePath),
		provider.WithScopes(scopes...),
		provider.WithUserInfoSignatureKeyIDs(serverKeyID),
		provider.WithPARRequired(),
		provider.WithJAR(),
		provider.WithJARM(serverKeyID),
		provider.WithPrivateKeyJWTAuthn(jose.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCERequired(goidc.CodeChallengeMethodSHA256),
		provider.WithRefreshTokenGrant(),
		provider.WithShouldIssueRefreshTokenFunc(issueRefreshToken),
		provider.WithRefreshTokenLifetimeSecs(6000),
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
		provider.WithStaticClient(client("client_one", clientOneJWKSFilePath)),
		provider.WithStaticClient(client("client_two", clientTwoJWKSFilePath)),
		provider.WithUnregisteredRedirectURIsForPAR(),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := op.RunTLS(provider.TLSOptions{
		TLSAddress: port,
		ServerCert: certFilePath,
		ServerKey:  certKeyFilePath,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}); err != nil {
		log.Fatal(err)
	}
}

func client(id, jwksFilepath string) *goidc.Client {
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
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  jwksBytes,
			ScopeIDs:    strings.Join(scopesIDs, " "),
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
