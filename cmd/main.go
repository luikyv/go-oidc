package main

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"github.com/luikymagno/auth-server/pkg/oidc"
)

func runFapi2OpenIdProvider() {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	port := ":83"
	mtlsPort := ":84"
	issuer := "https://host.docker.internal" + port
	mtlsIssuer := "https://host.docker.internal" + mtlsPort
	ps256ServerKeyId := "ps256_key"
	redirectUri := "https://localhost:8443/test/a/first_test/callback"
	scopes := []string{constants.OpenIdScope, constants.OffilineAccessScope, constants.EmailScope}

	// Create the manager.
	openidProvider := oidc.NewProvider(
		issuer,
		inmemory.NewInMemoryClientManager(),
		inmemory.NewInMemoryAuthnSessionManager(),
		inmemory.NewInMemoryGrantSessionManager(),
		GetPrivateJwks("server_keys/jwks.json"),
		ps256ServerKeyId,
		ps256ServerKeyId,
	)
	openidProvider.SetFapi2Profile()
	openidProvider.EnableMtls(mtlsIssuer)
	openidProvider.RequirePushedAuthorizationRequests(60)
	openidProvider.EnableJwtSecuredAuthorizationRequests(600, jose.PS256)
	openidProvider.EnableJwtSecuredAuthorizationResponseMode(600, ps256ServerKeyId)
	openidProvider.EnablePrivateKeyJwtClientAuthn(600, jose.PS256)
	openidProvider.EnableSelfSignedTlsClientAuthn()
	openidProvider.EnableTlsBoundTokens()
	openidProvider.EnableIssuerResponseParameter()
	openidProvider.EnableClaimsParameter()
	openidProvider.EnableDemonstrationProofOfPossesion(600, jose.PS256, jose.ES256)
	openidProvider.RequireProofKeyForCodeExchange(constants.Sha256CodeChallengeMethod)
	openidProvider.EnableRefreshTokenGrantType(6000, false)
	openidProvider.SetScopes(scopes...)
	openidProvider.SetSupportedUserClaims(constants.EmailClaim, constants.EmailVerifiedClaim)
	openidProvider.SetSupportedAuthenticationContextReferences("urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze")
	openidProvider.SetTokenOptions(func(c models.Client, s string) (models.TokenOptions, error) {
		return models.TokenOptions{
			TokenFormat:        constants.JwtTokenFormat,
			TokenExpiresInSecs: 600,
			ShouldRefresh:      true,
		}, nil
	})

	// Create Client Mocks.
	clientOneJwk := GetPrivateJwks("client_keys/client_one_jwks.json").Keys[0]
	openidProvider.AddClient(models.Client{
		Id: "client_one",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod:  constants.TlsAuthn,
			RedirectUris: []string{redirectUri},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []constants.GrantType{
				constants.AuthorizationCodeGrant,
				constants.RefreshTokenGrant,
			},
			ResponseTypes: []constants.ResponseType{
				constants.CodeResponse,
			},
			PublicJwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientOneJwk.Public()}},
		},
	})
	clientTwoJwk := GetPrivateJwks("client_keys/client_two_jwks.json").Keys[0]
	openidProvider.AddClient(models.Client{
		Id: "client_two",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod:  constants.TlsAuthn,
			RedirectUris: []string{redirectUri},
			Scopes:       strings.Join(scopes, " "),
			GrantTypes: []constants.GrantType{
				constants.AuthorizationCodeGrant,
				constants.RefreshTokenGrant,
			},
			ResponseTypes: []constants.ResponseType{
				constants.CodeResponse,
			},
			PublicJwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{clientTwoJwk.Public()}},
		},
	})

	// Create Policy
	openidProvider.AddPolicy(utils.NewPolicy(
		"policy",
		func(ctx utils.Context, client models.Client, session models.AuthnSession) bool { return true },
		AuthenticateUserWithNoInteraction,
	))

	// Run
	openidProvider.RunTls(oidc.TlsOptions{
		TlsAddress:                     port,
		ServerCertificate:              "server_keys/cert.pem",
		ServerKey:                      "server_keys/key.pem",
		CipherSuites:                   constants.FapiAllowedCipherSuites,
		MtlsAddress:                    mtlsPort,
		UnsecureCertificatesAreAllowed: true,
	})
}

func main() {
	runFapi2OpenIdProvider()
}
