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

func main() {
	// TODO: Find a way to pass the http client.
	// TODO: Only use necessary configs.
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)
	jwksFilePath := filepath.Join(sourceDir, "../keys/jwks.json")
	certFilePath := filepath.Join(sourceDir, "../keys/cert.pem")
	certKeyFilePath := filepath.Join(sourceDir, "../keys/key.pem")

	serverKeyID := "rs256_key"
	scopes := []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeEmail}

	// Create and configure the OpenID provider.
	op, err := provider.New(
		issuer,
		privateJWKS(jwksFilePath),
		provider.WithScopes(scopes...),
		provider.WithPAR(),
		provider.WithJAR(),
		provider.WithJARM(serverKeyID),
		provider.WithPrivateKeyJWTAuthn(jose.RS256),
		provider.WithBasicSecretAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(),
		provider.WithShouldIssueRefreshTokenFunc(issueRefreshToken),
		provider.WithRefreshTokenLifetimeSecs(6000),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(dcrPlugin(scopes)),
		provider.WithTokenOptions(tokenOptions(serverKeyID)),
		provider.WithOutterAuthorizationParamsRequired(),
		provider.WithPolicy(policy()),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := op.RunTLS(provider.TLSOptions{
		TLSAddress: port,
		ServerCert: certFilePath,
		ServerKey:  certKeyFilePath,
	}); err != nil {
		log.Fatal(err)
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

func privateJWKS(filename string) jose.JSONWebKeySet {
	absPath, _ := filepath.Abs(filename)
	clientJWKSFile, err := os.Open(absPath)
	if err != nil {
		log.Fatal(err)
	}
	defer clientJWKSFile.Close()

	clientJWKSBytes, err := io.ReadAll(clientJWKSFile)
	if err != nil {
		log.Fatal(err)
	}

	var clientJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(clientJWKSBytes, &clientJWKS); err != nil {
		log.Fatal(err)
	}

	return clientJWKS
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
