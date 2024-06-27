package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/luikymagno/goidc/pkg/goidcp"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func RunFAPI2OpenIDProvider() error {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	port := ":83"
	mtlsPort := ":84"
	issuer := "https://host.docker.internal" + port
	mtlsIssuer := "https://host.docker.internal" + mtlsPort
	ps256ServerKeyID := "ps256_key"
	redirectURI := "https://localhost:8443/test/a/first_test/callback"
	scopes := []string{goidc.OpenIDScope, goidc.OffilineAccessScope, goidc.EmailScope}

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
		goidcp.NewMongoDBClientManager(database),
		goidcp.NewMongoDBAuthnSessionManager(database),
		goidcp.NewMongoDBGrantSessionManager(database),
		GetPrivateJWKS("server_keys/jwks.json"),
		ps256ServerKeyID,
		ps256ServerKeyID,
	)
	openidProvider.SetFAPI2Profile()
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
	openidProvider.RequireProofKeyForCodeExchange(goidc.SHA256CodeChallengeMethod)
	openidProvider.EnableRefreshTokenGrantType(6000, false)
	openidProvider.SetScopes(scopes...)
	openidProvider.SetSupportedUserClaims(
		goidc.EmailClaim,
		goidc.EmailVerifiedClaim,
	)
	openidProvider.SetSupportedAuthenticationContextReferences(
		goidc.MaceIncommonIAPBronzeACR,
		goidc.MaceIncommonIAPSilverACR,
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
		clientOnePublicJWKS.Keys = append(clientOnePublicJWKS.Keys, jwk.GetPublic())
	}
	openidProvider.AddClient(goidc.Client{
		ID: "client_one",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.PrivateKeyJWTAuthn,
			RedirectURIS: []string{redirectURI},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
			},
			PublicJWKS: &clientOnePublicJWKS,
		},
	})
	clientTwoPrivateJWKS := GetPrivateJWKS("client_keys/client_two_jwks.json")
	clientTwoPublicJWKS := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{}}
	for _, jwk := range clientTwoPrivateJWKS.Keys {
		clientTwoPublicJWKS.Keys = append(clientTwoPublicJWKS.Keys, jwk.GetPublic())
	}
	openidProvider.AddClient(goidc.Client{
		ID: "client_two",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.PrivateKeyJWTAuthn,
			RedirectURIS: []string{redirectURI},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
			},
			PublicJWKS: &clientTwoPublicJWKS,
		},
	})

	// Create Policy
	openidProvider.AddPolicy(goidc.NewPolicy(
		"policy",
		func(ctx goidc.Context, client goidc.Client, session *goidc.AuthnSession) bool { return true },
		AuthenticateUser,
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
