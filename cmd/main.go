package main

import (
	"crypto/tls"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"github.com/luikymagno/auth-server/pkg/oidc"
)

func main() {
	//TODO: remove this.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	port := ":83"
	mtlsPort := ":84"
	issuer := "https://host.docker.internal" + port
	mtlsIssuer := "https://host.docker.internal" + mtlsPort
	privatePs256Jwk := unit.GetTestPrivatePs256Jwk("ps256_server_key")
	privateRs256Jwk := unit.GetTestPrivateRs256Jwk("rsa256_server_key")

	// Create the manager.
	openidProvider := oidc.NewProvider(
		issuer,
		inmemory.NewInMemoryClientManager(),
		inmemory.NewInMemoryAuthnSessionManager(),
		inmemory.NewInMemoryGrantSessionManager(),
		jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privatePs256Jwk, privateRs256Jwk}},
		privatePs256Jwk.KeyID,
		privatePs256Jwk.KeyID,
	)
	openidProvider.EnableMtls(mtlsIssuer)
	openidProvider.SetTokenOptions(func(c models.Client, s string) models.TokenOptions {
		return models.TokenOptions{
			TokenFormat:        constants.JwtTokenFormat,
			TokenExpiresInSecs: 600,
			ShouldRefresh:      true,
		}
	})
	openidProvider.EnablePushedAuthorizationRequests(60)
	openidProvider.EnableJwtSecuredAuthorizationRequests(600, jose.PS256, jose.RS256)
	openidProvider.EnableJwtSecuredAuthorizationResponseMode(600, privatePs256Jwk.KeyID)
	openidProvider.EnableSecretPostClientAuthn()
	openidProvider.EnableBasicSecretClientAuthn()
	openidProvider.EnablePrivateKeyJwtClientAuthn(600, jose.RS256, jose.PS256)
	openidProvider.EnableSelfSignedTlsClientAuthn()
	openidProvider.EnableTlsBoundTokens()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, jose.RS256, jose.PS256, jose.ES256)
	openidProvider.EnableProofKeyForCodeExchange(constants.Sha256CodeChallengeMethod)
	openidProvider.EnableImplicitGrantType()
	openidProvider.EnableRefreshTokenGrantType(6000, true)
	openidProvider.EnableDynamicClientRegistration(nil, true)
	openidProvider.SetScopes(constants.OffilineAccessScope, constants.EmailScope)
	openidProvider.SetSupportedUserClaims(constants.EmailClaim, constants.EmailVerifiedClaim)
	openidProvider.SetSupportedAuthenticationContextReferences("urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze")
	openidProvider.ConfigureFapi2Profile()

	// Client one.
	privateClientOneJwks := GetClientPrivateJwks("client_keys/client_one_jwks.json")
	clientOne := models.GetTestClientWithPrivateKeyJwtAuthn(issuer, privateClientOneJwks.Keys[0].Public())
	clientOne.RedirectUris = append(clientOne.RedirectUris, issuer+"/callback", "https://localhost:8443/test/a/first_test/callback")
	openidProvider.AddClient(clientOne)
	// Client two.
	privateClientTwoJwks := GetClientPrivateJwks("client_keys/client_two_jwks.json")
	clientTwo := models.GetTestClientWithPrivateKeyJwtAuthn(issuer, privateClientTwoJwks.Keys[0].Public())
	clientTwo.Id = "random_client_id_two"
	clientTwo.RedirectUris = append(clientTwo.RedirectUris, issuer+"/callback", "https://localhost:8443/test/a/first_test/callback")
	openidProvider.AddClient(clientTwo)

	// Create Policy
	policy := utils.NewPolicy(
		"policy",
		func(ctx utils.Context, client models.Client, session models.AuthnSession) bool { return true },
		NoInteractionAuthnFunc,
	)
	openidProvider.AddPolicy(policy)

	// Run
	openidProvider.RunTls(oidc.TlsOptions{
		TlsAddress:        port,
		MtlsAddress:       mtlsPort,
		ServerCertificate: "server_keys/cert.pem",
		ServerKey:         "server_keys/key.pem",
	})
}
