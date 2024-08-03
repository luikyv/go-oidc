package main

import (
	"crypto/tls"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/goidc/provider"
)

func main() {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	serverKeyID := "rs256_key"
	scopes := []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOffilineAccess, goidc.ScopeEmail}

	// Create and configure the manager.
	openidProvider, err := provider.New(
		Issuer,
		PrivateJWKS("server_keys/jwks.json"),
		serverKeyID,
		provider.WithScopes(scopes...),
		provider.WithPAR(60),
		provider.WithJAR(600, jose.RS256),
		provider.WithJARM(600, serverKeyID),
		provider.WithPrivateKeyJWTAuthn(600, jose.RS256),
		provider.WithBasicSecretAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithDPoP(600, jose.RS256, jose.PS256, jose.ES256),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithRefreshTokenGrant(6000, false),
		provider.WithUserClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(func(ctx goidc.Context, clientInfo *goidc.ClientMetaInfo) {
			clientInfo.Scopes = goidc.Scopes(scopes).String()
		}, true),
		provider.WithTokenOptions(func(c *goidc.Client, s string) (goidc.TokenOptions, error) {
			return goidc.NewJWTTokenOptions(serverKeyID, 600), nil
		}),
		provider.WithPolicy(goidc.NewPolicy(
			"policy",
			func(ctx goidc.Context, client *goidc.Client, session *goidc.AuthnSession) bool { return true },
			AuthenticateUserWithNoInteraction,
		)),
	)
	if err != nil {
		panic(err.Error())
	}

	if err := openidProvider.RunTLS(provider.TLSOptions{
		TLSAddress:        Port,
		ServerCertificate: "server_keys/cert.pem",
		ServerKey:         "server_keys/key.pem",
	}); err != nil {
		panic(err.Error())
	}
}
