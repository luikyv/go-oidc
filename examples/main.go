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
	openidProvider := provider.New(
		Issuer,
		PrivateJWKS("server_keys/jwks.json"),
		serverKeyID,
	)
	openidProvider.EnablePushedAuthorizationRequests(60)
	openidProvider.EnableJWTSecuredAuthorizationRequests(600, jose.RS256)
	openidProvider.EnableJWTSecuredAuthorizationResponseMode(600, serverKeyID)
	openidProvider.EnablePrivateKeyJWTClientAuthn(600, jose.RS256)
	openidProvider.EnableBasicSecretClientAuthn()
	openidProvider.EnableSecretPostClientAuthn()
	openidProvider.EnableSelfSignedTLSClientAuthn()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, jose.RS256, jose.PS256, jose.ES256)
	openidProvider.EnableProofKeyForCodeExchange(goidc.CodeChallengeMethodSHA256)
	openidProvider.EnableRefreshTokenGrantType(6000, false)
	openidProvider.SetScopes(scopes...)
	openidProvider.SetSupportedUserClaims(
		goidc.ClaimEmail,
		goidc.ClaimEmailVerified,
	)
	openidProvider.SetSupportedAuthenticationContextReferences(
		goidc.ACRMaceIncommonIAPBronze,
		goidc.ACRMaceIncommonIAPSilver,
	)
	openidProvider.EnableDynamicClientRegistration(func(ctx goidc.Context, clientInfo *goidc.ClientMetaInfo) {
		clientInfo.Scopes = goidc.Scopes(scopes).String()
	}, true)
	openidProvider.SetTokenOptions(func(c *goidc.Client, s string) (goidc.TokenOptions, error) {
		return goidc.NewJWTTokenOptions(serverKeyID, 600), nil
	})

	openidProvider.AddPolicy(goidc.NewPolicy(
		"policy",
		func(ctx goidc.Context, client *goidc.Client, session *goidc.AuthnSession) bool { return true },
		AuthenticateUserWithNoInteraction,
	))

	if err := openidProvider.RunTLS(provider.TLSOptions{
		TLSAddress:        Port,
		ServerCertificate: "server_keys/cert.pem",
		ServerKey:         "server_keys/key.pem",
	}); err != nil {
		panic(err.Error())
	}
}
