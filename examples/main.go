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

func runFapi2OpenIdProvider() error {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	port := ":83"
	mtlsPort := ":84"
	issuer := "https://host.docker.internal" + port
	mtlsIssuer := "https://host.docker.internal" + mtlsPort
	ps256ServerKeyId := "ps256_key"
	redirectUri := "https://localhost:8443/test/a/first_test/callback"
	scopes := []string{goidc.OpenIdScope, goidc.OffilineAccessScope, goidc.EmailScope}

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
		goidcp.NewMongoDbClientManager(database),
		goidcp.NewMongoDbAuthnSessionManager(database),
		goidcp.NewMongoDBGrantSessionManager(database),
		GetPrivateJwks("server_keys/jwks.json"),
		ps256ServerKeyId,
		ps256ServerKeyId,
	)
	openidProvider.SetFapi2Profile()
	openidProvider.EnableMtls(mtlsIssuer)
	openidProvider.RequirePushedAuthorizationRequests(60)
	openidProvider.EnableJwtSecuredAuthorizationRequests(600, goidc.PS256)
	openidProvider.EnableJwtSecuredAuthorizationResponseMode(600, ps256ServerKeyId)
	openidProvider.EnablePrivateKeyJwtClientAuthn(600, goidc.PS256)
	openidProvider.EnableSelfSignedTlsClientAuthn()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, goidc.PS256, goidc.ES256)
	openidProvider.EnableTlsBoundTokens()
	openidProvider.RequireSenderConstrainedTokens()
	openidProvider.RequireProofKeyForCodeExchange(goidc.Sha256CodeChallengeMethod)
	openidProvider.EnableRefreshTokenGrantType(6000, false)
	openidProvider.SetScopes(scopes...)
	openidProvider.SetSupportedUserClaims(
		goidc.EmailClaim,
		goidc.EmailVerifiedClaim,
	)
	openidProvider.SetSupportedAuthenticationContextReferences(
		goidc.MaceIncommonIapBronzeAcr,
		goidc.MaceIncommonIapSilverAcr,
	)
	openidProvider.EnableDynamicClientRegistration(nil, true)
	openidProvider.SetTokenOptions(func(c goidc.Client, s string) (goidc.TokenOptions, error) {
		return goidc.NewJwtTokenOptions(ps256ServerKeyId, 600, true), nil
	})
	openidProvider.EnableUserInfoEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	openidProvider.EnableJwtSecuredAuthorizationResponseModeEncryption(
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)

	// Create Client Mocks.
	clientOnePrivateJwks := GetPrivateJwks("client_keys/client_one_jwks.json")
	clientOnePublicJwks := goidc.JsonWebKeySet{Keys: []goidc.JsonWebKey{}}
	for _, jwk := range clientOnePrivateJwks.Keys {
		clientOnePublicJwks.Keys = append(clientOnePublicJwks.Keys, jwk.GetPublic())
	}
	openidProvider.AddClient(goidc.Client{
		Id: "client_one",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.PrivateKeyJwtAuthn,
			RedirectUris: []string{redirectUri},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
			},
			PublicJwks: &clientOnePublicJwks,
			// IdTokenKeyEncryptionAlgorithm:      jose.RSA_OAEP,
			// IdTokenContentEncryptionAlgorithm:  jose.A128CBC_HS256,
			// UserInfoSignatureAlgorithm:         jose.PS256,
			// UserInfoKeyEncryptionAlgorithm:     jose.RSA_OAEP,
			// UserInfoContentEncryptionAlgorithm: jose.A128CBC_HS256,
			// JarmKeyEncryptionAlgorithm:     jose.RSA_OAEP,
			// JarmContentEncryptionAlgorithm: jose.A128CBC_HS256,
		},
	})
	clientTwoPrivateJwks := GetPrivateJwks("client_keys/client_two_jwks.json")
	clientTwoPublicJwks := goidc.JsonWebKeySet{Keys: []goidc.JsonWebKey{}}
	for _, jwk := range clientTwoPrivateJwks.Keys {
		clientTwoPublicJwks.Keys = append(clientTwoPublicJwks.Keys, jwk.GetPublic())
	}
	openidProvider.AddClient(goidc.Client{
		Id: "client_two",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.PrivateKeyJwtAuthn,
			RedirectUris: []string{redirectUri},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
			},
			PublicJwks: &clientTwoPublicJwks,
		},
	})

	// Create Policy
	openidProvider.AddPolicy(goidc.NewPolicy(
		"policy",
		func(ctx goidc.Context, client goidc.Client, session *goidc.AuthnSession) bool { return true },
		AuthenticateUserWithNoInteraction,
	))

	// Run
	return openidProvider.RunTls(goidcp.TlsOptions{
		TlsAddress:                     port,
		ServerCertificate:              "server_keys/cert.pem",
		ServerKey:                      "server_keys/key.pem",
		CipherSuites:                   goidc.FapiAllowedCipherSuites,
		MtlsAddress:                    mtlsPort,
		UnsecureCertificatesAreAllowed: true,
	})
}

func main() {
	err := runFapi2OpenIdProvider()
	if err != nil {
		panic(err.Error())
	}
}
