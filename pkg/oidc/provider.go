package oidc

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OpenIdProvider struct {
	utils.Configuration
}

func NewProvider(
	host string,
	clientManager crud.ClientManager,
	authnSessionManager crud.AuthnSessionManager,
	grantSessionManager crud.GrantSessionManager,
	privateJwks jose.JSONWebKeySet,
	defaultTokenKeyId string,
	defaultIdTokenKeyId string,
	templates string,
) *OpenIdProvider {
	provider := &OpenIdProvider{
		Configuration: utils.Configuration{
			Host:                host,
			Profile:             constants.OpenIdProfile,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			Scopes:              []string{constants.OpenIdScope},
			GetTokenOptions: func(client models.Client, scopes string) models.TokenOptions {
				return models.TokenOptions{
					TokenExpiresInSecs: constants.DefaultTokenLifetimeSecs,
					TokenFormat:        constants.JwtTokenFormat,
				}
			},
			PrivateJwks:                  privateJwks,
			DefaultTokenSignatureKeyId:   defaultTokenKeyId,
			DefaultIdTokenSignatureKeyId: defaultIdTokenKeyId,
			IdTokenSignatureKeyIds:       []string{defaultIdTokenKeyId},
			IdTokenExpiresInSecs:         600,
			CustomIdTokenClaims:          []constants.Claim{},
			GrantTypes: []constants.GrantType{
				constants.ClientCredentialsGrant,
				constants.AuthorizationCodeGrant,
			},
			ResponseTypes: []constants.ResponseType{constants.CodeResponse},
			ResponseModes: []constants.ResponseMode{
				constants.QueryResponseMode,
				constants.FragmentResponseMode,
				constants.FormPostResponseMode,
			},
			ClientAuthnMethods:               []constants.ClientAuthnType{},
			DpopSignatureAlgorithms:          []jose.SignatureAlgorithm{},
			SubjectIdentifierTypes:           []constants.SubjectIdentifierType{constants.PublicSubjectIdentifier},
			AuthenticationSessionTimeoutSecs: constants.DefaultAuthenticationSessionTimeoutSecs,
		},
	}

	return provider
}

func (provider *OpenIdProvider) validateConfiguration() {

	defaultIdTokenSignatureKey := provider.PrivateJwks.Key(provider.DefaultIdTokenSignatureKeyId)[0]
	if provider.Profile == constants.OpenIdProfile && defaultIdTokenSignatureKey.Algorithm != string(jose.RS256) {
		panic("the default signature algorithm for ID tokens must be RS256")
	}

	defaultJarmSignatureKey := provider.PrivateJwks.Key(provider.DefaultJarmSignatureKeyId)[0]
	if provider.Profile == constants.OpenIdProfile && defaultJarmSignatureKey.Algorithm != string(jose.RS256) {
		panic("the default signature algorithm for JARM must be RS256")
	}

	for _, signatureAlgorithm := range provider.PrivateKeyJwtSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			panic("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	for _, signatureAlgorithm := range provider.ClientSecretJwtSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			panic("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	if !unit.ContainsAll(provider.ClientAuthnMethods, provider.IntrospectionClientAuthnMethods...) ||
		slices.Contains(provider.IntrospectionClientAuthnMethods, constants.NoneAuthn) {
		panic("invalid client authentication method for token introspection")
	}
}

func (provider *OpenIdProvider) SetCustomIdTokenClaims(claims ...constants.Claim) {
	provider.CustomIdTokenClaims = claims
}

func (provider *OpenIdProvider) AddIdTokenSignatureKeyIds(idTokenSignatureKeyIds ...string) {
	if !unit.ContainsAll(idTokenSignatureKeyIds, provider.DefaultIdTokenSignatureKeyId) {
		idTokenSignatureKeyIds = append(idTokenSignatureKeyIds, provider.DefaultIdTokenSignatureKeyId)
	}
	provider.IdTokenSignatureKeyIds = idTokenSignatureKeyIds
}

func (provider *OpenIdProvider) SetIdTokenLifetime(idTokenLifetimeSecs int) {
	provider.IdTokenExpiresInSecs = idTokenLifetimeSecs
}

func (provider *OpenIdProvider) EnableDynamicClientRegistration(dcrPlugin utils.DcrPluginFunc, shouldRotateTokens bool) {
	provider.DcrIsEnabled = true
	provider.DcrPlugin = dcrPlugin
	provider.ShouldRotateRegistrationTokens = shouldRotateTokens

}

func (provider *OpenIdProvider) EnableRefreshTokenGrantType(refreshTokenLifetimeSecs int, shouldRotateTokens bool) {
	provider.GrantTypes = append(provider.GrantTypes, constants.RefreshTokenGrant)
	provider.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	provider.ShouldRotateRefreshTokens = shouldRotateTokens
}

func (provider *OpenIdProvider) RequireOpenIdScope() {
	provider.OpenIdScopeIsRequired = true
}

func (provider *OpenIdProvider) SetTokenOptions(getTokenOpts utils.GetTokenOptionsFunc) {
	provider.GetTokenOptions = getTokenOpts
}

func (provider *OpenIdProvider) EnableImplicitGrantType() {
	provider.GrantTypes = append(provider.GrantTypes, constants.ImplicitGrant)
	provider.ResponseTypes = append(
		provider.ResponseTypes,
		constants.TokenResponse,
		constants.IdTokenResponse,
		constants.IdTokenAndTokenResponse,
		constants.CodeAndIdTokenResponse,
		constants.CodeAndTokenResponse,
		constants.CodeAndIdTokenAndTokenResponse,
	)
}

func (provider *OpenIdProvider) SetScopes(scopes ...string) {
	if slices.Contains(scopes, constants.OpenIdScope) {
		provider.Scopes = scopes
	} else {
		provider.Scopes = append(scopes, constants.OpenIdScope)
	}
}

func (provider *OpenIdProvider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.ParLifetimeSecs = parLifetimeSecs
	provider.ParIsEnabled = true
}

func (provider *OpenIdProvider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.EnablePushedAuthorizationRequests(parLifetimeSecs)
	provider.ParIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationRequests(
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.JarIsEnabled = true
	provider.JarSignatureAlgorithms = jarAlgorithms
}

func (provider *OpenIdProvider) RequireJwtSecuredAuthorizationRequests(
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableJwtSecuredAuthorizationRequests(jarAlgorithms...)
	provider.JarIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJarmSignatureKeyId string,
	jarmSignatureKeyIds ...string,
) {
	if !unit.ContainsAll(jarmSignatureKeyIds, defaultJarmSignatureKeyId) {
		jarmSignatureKeyIds = append(jarmSignatureKeyIds, defaultJarmSignatureKeyId)
	}

	provider.JarmIsEnabled = true
	provider.ResponseModes = append(
		provider.ResponseModes,
		constants.JwtResponseMode,
		constants.QueryJwtResponseMode,
		constants.FragmentJwtResponseMode,
		constants.FormPostJwtResponseMode,
	)
	provider.JarmLifetimeSecs = jarmLifetimeSecs
	provider.DefaultJarmSignatureKeyId = defaultJarmSignatureKeyId
	provider.JarmSignatureKeyIds = jarmSignatureKeyIds

}

func (provider *OpenIdProvider) EnableBasicSecretClientAuthn() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.ClientSecretBasicAuthn)
}

func (provider *OpenIdProvider) EnableSecretPostClientAuthn() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.ClientSecretPostAuthn)
}

func (provider *OpenIdProvider) EnablePrivateKeyJwtClientAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.PrivateKeyJwtAuthn)
	provider.PrivateKeyJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.PrivateKeyJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableClientSecretJwtAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.ClientSecretBasicAuthn)
	provider.ClientSecretJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.ClientSecretJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableTlsClientAuthn(mtlsHost string, selfSignedCertificatesAreAllowed bool) {
	provider.MtlsHost = mtlsHost
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.TlsAuthn)
	if selfSignedCertificatesAreAllowed {
		provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.SelfSignedTlsAuthn)
	}
}

func (provider *OpenIdProvider) SupportPublicClients() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.NoneAuthn)
}

func (provider *OpenIdProvider) EnableIssuerResponseParameter() {
	provider.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.DpopIsEnabled = true
	provider.DpopLifetimeSecs = dpopLifetimeSecs
	provider.DpopSignatureAlgorithms = dpopSigningAlgorithms
}

func (provider *OpenIdProvider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	provider.DpopIsRequired = true
}

func (provider *OpenIdProvider) EnableTokenIntrospection(clientAuthnMethods ...constants.ClientAuthnType) {
	provider.IntrospectionIsEnabled = true
	provider.IntrospectionClientAuthnMethods = clientAuthnMethods
	provider.GrantTypes = append(provider.GrantTypes, constants.IntrospectionGrant)
}

func (provider *OpenIdProvider) EnableProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.CodeChallengeMethods = codeChallengeMethods
	provider.PkceIsEnabled = true
}

func (provider *OpenIdProvider) RequireProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	provider.PkceIsRequired = true
}

func (provider *OpenIdProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.AuthenticationSessionTimeoutSecs = timeoutSecs
}

func (provider *OpenIdProvider) AddClient(client models.Client) error {
	return provider.ClientManager.Create(client)
}

func (provider *OpenIdProvider) AddPolicy(policy utils.AuthnPolicy) {
	provider.Policies = append(provider.Policies, policy)
}

func (provider OpenIdProvider) prepareAndGetContext(req *http.Request, resp http.ResponseWriter) utils.Context {
	// TODO Middleware?
	correlationId := uuid.NewString()
	correlationIdHeader, ok := req.Header[string(constants.CorrelationIdHeader)]
	if ok && len(correlationIdHeader) > 0 {
		correlationId = correlationIdHeader[0]
	}

	// Avoiding caching.
	resp.Header().Set("Cache-Control", "no-cache, no-store")
	resp.Header().Set("Pragma", "no-cache")
	// Return the correlation ID.
	resp.Header().Set(string(constants.CorrelationIdHeader), correlationId)

	// Create the logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	// Set shared information.
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(constants.CorrelationIdKey, correlationId),
	)

	return utils.NewContext(provider.Configuration, req, resp, logger)
}

func (provider *OpenIdProvider) getServerHandler() http.Handler {

	serverHandler := http.NewServeMux()

	// Set endpoints.
	serverHandler.HandleFunc(
		"GET "+string(constants.JsonWebKeySetEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleJWKSRequest(provider.prepareAndGetContext(r, w))
		},
	)

	if provider.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(provider.prepareAndGetContext(r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(constants.AuthorizationEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeRequest(provider.prepareAndGetContext(r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.AuthorizationEndpoint)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeCallbackRequest(provider.prepareAndGetContext(r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(provider.prepareAndGetContext(r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.WellKnownEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleWellKnownRequest(provider.prepareAndGetContext(r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(provider.prepareAndGetContext(r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(provider.prepareAndGetContext(r, w))
		},
	)

	if provider.DcrIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.DynamicClientEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientCreation(provider.prepareAndGetContext(r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientUpdate(provider.prepareAndGetContext(r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientRetrieve(provider.prepareAndGetContext(r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientDelete(provider.prepareAndGetContext(r, w))
			},
		)
	}

	if provider.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(provider.prepareAndGetContext(r, w))
			},
		)
	}

	return serverHandler
}

func (provider *OpenIdProvider) getMtlsServerHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+string(constants.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(provider.prepareAndGetContext(r, w))
		},
	)

	if provider.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(provider.prepareAndGetContext(r, w))
			},
		)
	}

	//TODO: Add other endpoints.

	return apihandlers.NewAddCertificateHeaderMiddlewareHandler(serverHandler)
}

func (provider *OpenIdProvider) Run(address string) error {
	provider.validateConfiguration()
	serverHandler := provider.getServerHandler()
	return http.ListenAndServe(address, serverHandler)
}

// This is not recommended to use in production.
func (provider *OpenIdProvider) RunTLS(address string, mtlsAddress string) error {

	provider.validateConfiguration()

	if provider.IsTlsClientAuthnEnabled() {
		server := &http.Server{
			Addr:    mtlsAddress,
			Handler: provider.getMtlsServerHandler(),
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAnyClientCert,
			},
		}
		go server.ListenAndServeTLS("cert.pem", "key.pem")
	}

	serverHandler := provider.getServerHandler()
	return http.ListenAndServeTLS(address, "cert.pem", "key.pem", serverHandler)
}
