package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
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
) *OpenIdProvider {
	provider := &OpenIdProvider{
		Configuration: utils.Configuration{
			Host:                host,
			Profile:             constants.OpenIdProfile,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			Scopes:              []string{string(constants.OpenIdScope)},
			GetTokenOptions: func(client models.Client, scopes string) (models.TokenOptions, error) {
				return models.TokenOptions{
					TokenExpiresInSecs: constants.DefaultTokenLifetimeSecs,
					TokenFormat:        constants.JwtTokenFormat,
				}, nil
			},
			PrivateJwks:                  privateJwks,
			DefaultTokenSignatureKeyId:   defaultTokenKeyId, // TODO: make sure is valid
			DefaultIdTokenSignatureKeyId: defaultIdTokenKeyId,
			IdTokenSignatureKeyIds:       []string{defaultIdTokenKeyId},
			IdTokenExpiresInSecs:         600,
			UserClaims:                   []string{},
			GrantTypes: []constants.GrantType{
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
			ClaimTypes:                       []constants.ClaimType{constants.NormalClaimType},
			AuthenticationSessionTimeoutSecs: constants.DefaultAuthenticationSessionTimeoutSecs,
			CorrelationIdHeader:              constants.CorrelationIdHeader,
		},
	}

	return provider
}

// TODO: log warnings instead.
// func (provider *OpenIdProvider) validateConfiguration() {
// 	if provider.Profile == constants.OpenIdProfile {
// 		defaultIdTokenSignatureKey := provider.PrivateJwks.Key(provider.DefaultIdTokenSignatureKeyId)[0]
// 		if defaultIdTokenSignatureKey.Algorithm != string(jose.RS256) {
// 			panic("the default signature algorithm for ID tokens must be RS256")
// 		}

// 		defaultJarmSignatureKey := provider.PrivateJwks.Key(provider.DefaultJarmSignatureKeyId)[0]
// 		if defaultJarmSignatureKey.Algorithm != string(jose.RS256) {
// 			panic("the default signature algorithm for JARM must be RS256")
// 		}
// 	}

// 	if provider.Profile == constants.Fapi2Profile {

// 		if slices.Contains(provider.GrantTypes, constants.ImplicitGrant) {
// 			panic("the implict grant is not allowed for FAPI 2.0")
// 		}

// 		if !provider.ParIsEnabled || !provider.ParIsRequired {
// 			panic("pushed authorization requests is required for FAPI 2.0")
// 		}

// 		if !provider.PkceIsEnabled || !provider.PkceIsRequired {
// 			panic("proof key for code exchange is required for FAPI 2.0")
// 		}

// 		if !provider.IssuerResponseParameterIsEnabled {
// 			panic("the issuer response parameter is required for FAPI 2.0")
// 		}
// 	}

// 	for _, signatureAlgorithm := range provider.PrivateKeyJwtSignatureAlgorithms {
// 		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
// 			panic("symetric algorithms are not allowed for private_key_jwt authentication")
// 		}
// 	}

// 	for _, signatureAlgorithm := range provider.ClientSecretJwtSignatureAlgorithms {
// 		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
// 			panic("assymetric algorithms are not allowed for client_secret_jwt authentication")
// 		}
// 	}

// 	if !unit.ContainsAll(provider.ClientAuthnMethods, provider.IntrospectionClientAuthnMethods...) ||
// 		slices.Contains(provider.IntrospectionClientAuthnMethods, constants.NoneAuthn) {
// 		panic("invalid client authentication method for token introspection")
// 	}
// }

func (provider *OpenIdProvider) SetSupportedUserClaims(claims ...string) {
	provider.UserClaims = claims
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
	if slices.Contains(scopes, string(constants.OpenIdScope)) {
		provider.Scopes = scopes
	} else {
		provider.Scopes = append(scopes, string(constants.OpenIdScope))
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
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.JarIsEnabled = true
	provider.JarLifetimeSecs = jarLifetimeSecs
	provider.JarSignatureAlgorithms = jarAlgorithms
}

func (provider *OpenIdProvider) RequireJwtSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableJwtSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
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

// caCertPool is a reference to the certificate authorities' certificates that will be used to validate
// TLS client certificates during tls_client_auth.
func (provider *OpenIdProvider) EnableTlsClientAuthn(caCertPool *x509.CertPool) {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.TlsAuthn)
	provider.CaCertificatePool = caCertPool
}

func (provider *OpenIdProvider) EnableSelfSignedTlsClientAuthn() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.SelfSignedTlsAuthn)
}

func (provider *OpenIdProvider) EnableMtls(mtlsHost string) {
	provider.MtlsIsEnabled = true
	provider.MtlsHost = mtlsHost
}

func (provider *OpenIdProvider) EnableTlsBoundTokens() {
	provider.TlsBoundTokensIsEnabled = true
}

func (provider *OpenIdProvider) EnableNoneClientAuthn() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.NoneAuthn)
}

func (provider *OpenIdProvider) EnableIssuerResponseParameter() {
	provider.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableClaimsParameter() {
	provider.ClaimsParameterIsEnabled = true
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

func (provider *OpenIdProvider) RequireSenderConstrainedTokens() {
	provider.SenderConstrainedTokenIsRequired = true
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

func (provider *OpenIdProvider) SetSupportedAuthenticationContextReferences(
	acrValues ...constants.AuthenticationContextReference,
) {
	provider.AuthenticationContextReferences = acrValues
}

func (provider *OpenIdProvider) SetDisplayValuesSupported(values ...constants.DisplayValue) {
	provider.DisplayValues = values
}

func (provider *OpenIdProvider) SetClaimTypesSupported(types ...constants.ClaimType) {
	provider.ClaimTypes = types
}

func (provider *OpenIdProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.AuthenticationSessionTimeoutSecs = timeoutSecs
}

func (provider *OpenIdProvider) SetCorrelationIdHeader(header string) {
	provider.CorrelationIdHeader = header
}

func (provider *OpenIdProvider) SetFapi2Profile() {
	provider.Profile = constants.Fapi2Profile
}

func (provider *OpenIdProvider) AddClient(client models.Client) error {
	return provider.ClientManager.Create(client)
}

func (provider *OpenIdProvider) AddPolicy(policy utils.AuthnPolicy) {
	provider.Policies = append(provider.Policies, policy)
}

func (provider *OpenIdProvider) getServerHandler() http.Handler {

	serverHandler := http.NewServeMux()

	// Set endpoints.
	serverHandler.HandleFunc(
		"GET "+string(constants.JsonWebKeySetEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleJWKSRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	if provider.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.Configuration, r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(constants.AuthorizationEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.AuthorizationEndpoint)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeCallbackRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.WellKnownEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleWellKnownRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	if provider.DcrIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.DynamicClientEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientCreation(utils.NewContext(provider.Configuration, r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientUpdate(utils.NewContext(provider.Configuration, r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientRetrieve(utils.NewContext(provider.Configuration, r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientDelete(utils.NewContext(provider.Configuration, r, w))
			},
		)
	}

	if provider.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.Configuration, r, w))
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
			apihandlers.HandleTokenRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.Configuration, r, w))
		},
	)

	if provider.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.Configuration, r, w))
			},
		)
	}

	if provider.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.Configuration, r, w))
			},
		)
	}

	return serverHandler
}

func (provider *OpenIdProvider) Run(address string) error {
	serverHandler := apihandlers.NewAddCacheControlHeadersMiddlewareHandler(
		apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(provider.getServerHandler(), provider.CorrelationIdHeader),
	)
	return http.ListenAndServe(address, serverHandler)
}

type TlsOptions struct {
	TlsAddress        string
	MtlsAddress       string
	ServerCertificate string
	ServerKey         string
}

func (provider *OpenIdProvider) runMtls(config TlsOptions) error {
	handler := apihandlers.AddCertificateHeaderMiddlewareHandler(
		apihandlers.NewAddCacheControlHeadersMiddlewareHandler(
			apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(
				provider.getMtlsServerHandler(),
				provider.CorrelationIdHeader,
			),
		),
	)

	var cipherSuites []uint16
	if provider.Profile == constants.Fapi2Profile {
		cipherSuites = constants.FapiAllowedCipherSuites
	}
	server := &http.Server{
		Addr:    config.MtlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			// A client certificate is required, but its validation depends on the authentication method,
			// e.g. self signed certificate, ...
			ClientAuth:   tls.RequireAnyClientCert,
			CipherSuites: cipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIdProvider) RunTls(config TlsOptions) error {

	if provider.MtlsIsEnabled {
		go provider.runMtls(config)
	}

	handler := apihandlers.NewAddCacheControlHeadersMiddlewareHandler(
		apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(
			provider.getServerHandler(),
			provider.CorrelationIdHeader,
		),
	)

	//TODO: move this from here.
	var cipherSuites []uint16
	if provider.Profile == constants.Fapi2Profile {
		cipherSuites = constants.FapiAllowedCipherSuites
	}
	server := &http.Server{
		Addr:    config.TlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: cipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}
