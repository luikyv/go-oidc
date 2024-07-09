package main

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/luikymagno/goidc/pkg/goidcp"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func RunFAPI2OpenIDProvider() error {
	port := ":83"
	mtlsPort := ":84"
	issuer := "https://host.docker.internal" + port
	mtlsIssuer := "https://host.docker.internal" + mtlsPort
	ps256ServerKeyID := "ps256_key"
	redirectURI := "https://localhost:8443/test/a/first_test/callback"
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
		ps256ServerKeyID,
		ps256ServerKeyID,
	)
	openidProvider.SetProfileFAPI2()
	openidProvider.EnableMTLS(mtlsIssuer)
	openidProvider.RequirePushedAuthorizationRequests(60)
	openidProvider.EnableJWTSecuredAuthorizationRequests(600, goidc.PS256)
	openidProvider.EnableJWTSecuredAuthorizationResponseMode(600, ps256ServerKeyID)
	openidProvider.EnablePrivateKeyJWTClientAuthn(600, goidc.PS256)
	openidProvider.EnableSelfSignedTLSClientAuthn()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, goidc.PS256, goidc.ES256)
	openidProvider.EnableTLSBoundTokens()
	openidProvider.RequireSenderConstrainedTokens()
	openidProvider.RequireProofKeyForCodeExchange(goidc.CodeChallengeMethodSHA256)
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
	openidProvider.EnableDynamicClientRegistration(nil, true)
	openidProvider.SetTokenOptions(func(c goidc.Client, s string) (goidc.TokenOptions, error) {
		return goidc.NewJWTTokenOptions(ps256ServerKeyID, 600, true), nil
	})
	openidProvider.EnableUserInfoEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	openidProvider.EnableJWTSecuredAuthorizationResponseModeEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)

	// Create Client Mocks.
	clientOnePrivateJWKS := GetPrivateJWKS("client_keys/client_one_jwks.json")
	clientOnePublicJWKS := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{}}
	for _, jwk := range clientOnePrivateJWKS.Keys {
		clientOnePublicJWKS.Keys = append(clientOnePublicJWKS.Keys, jwk.Public())
	}
	openidProvider.AddClient(goidc.Client{
		ID: "client_one",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnPrivateKeyJWT,
			RedirectURIS: []string{redirectURI},
			Scopes:       goidc.Scopes(scopes).String(),
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
			},
			PublicJWKS: &clientOnePublicJWKS,
		},
	})
	clientTwoPrivateJWKS := GetPrivateJWKS("client_keys/client_two_jwks.json")
	clientTwoPublicJWKS := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{}}
	for _, jwk := range clientTwoPrivateJWKS.Keys {
		clientTwoPublicJWKS.Keys = append(clientTwoPublicJWKS.Keys, jwk.Public())
	}
	openidProvider.AddClient(goidc.Client{
		ID: "client_two",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnPrivateKeyJWT,
			RedirectURIS: []string{redirectURI},
			Scopes:       goidc.Scopes(scopes).String(),
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
			},
			PublicJWKS: &clientTwoPublicJWKS,
		},
	})

	// Create Policy
	openidProvider.AddPolicy(goidc.NewPolicy(
		"policy",
		func(ctx goidc.OAuthContext, client goidc.Client, session *goidc.AuthnSession) bool { return true },
		AuthenticateUserWithNoInteraction,
	))

	// Run
	return openidProvider.RunTLS(goidcp.TLSOptions{
		TLSAddress:                     port,
		ServerCertificate:              "server_keys/cert.pem",
		ServerKey:                      "server_keys/key.pem",
		CipherSuites:                   goidc.FAPIAllowedCipherSuites,
		MTLSAddress:                    mtlsPort,
		UnsecureCertificatesAreAllowed: true,
	})
}
