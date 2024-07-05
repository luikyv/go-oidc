package main

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/luikymagno/goidc/pkg/goidcp"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func RunOpenIDProvider() error {

	port := ":83"
	issuer := "https://host.docker.internal" + port
	serverKeyID := "rs256_key"
	scopes := []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOffilineAccess, goidc.ScopeEmail}

	// MongoDB
	options := options.Client().ApplyURI("mongodb://admin:password@localhost:27017")
	conn, err := mongo.Connect(context.Background(), options)
	if err != nil {
		panic(err)
	}
	database := conn.Database("goidc")

	// Create the manager.
	openidProvider := goidcp.NewProvider(
		issuer,
		goidcp.NewInMemoryClientManager(),
		goidcp.NewMongoDBAuthnSessionManager(database),
		goidcp.NewMongoDBGrantSessionManager(database),
		GetPrivateJWKS("server_keys/jwks.json"),
		serverKeyID,
		serverKeyID,
	)
	openidProvider.EnablePushedAuthorizationRequests(60)
	openidProvider.EnableJWTSecuredAuthorizationRequests(600, goidc.RS256)
	openidProvider.EnableJWTSecuredAuthorizationResponseMode(600, serverKeyID)
	openidProvider.EnablePrivateKeyJWTClientAuthn(600, goidc.RS256)
	openidProvider.EnableBasicSecretClientAuthn()
	openidProvider.EnableSecretPostClientAuthn()
	openidProvider.EnableSelfSignedTLSClientAuthn()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, goidc.RS256, goidc.PS256, goidc.ES256)
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
	openidProvider.SetTokenOptions(func(c goidc.Client, s string) (goidc.TokenOptions, error) {
		return goidc.NewJWTTokenOptions(serverKeyID, 600, true), nil
	})

	// Create Policy
	openidProvider.AddPolicy(goidc.NewPolicy(
		"policy",
		func(ctx goidc.Context, client goidc.Client, session *goidc.AuthnSession) bool { return true },
		AuthenticateUserWithNoInteraction,
	))

	// Run
	return openidProvider.RunTLS(goidcp.TLSOptions{
		TLSAddress:        port,
		ServerCertificate: "server_keys/cert.pem",
		ServerKey:         "server_keys/key.pem",
		CipherSuites:      goidc.FAPIAllowedCipherSuites,
	})
}
