package goidcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/apihandlers"
	"github.com/luikymagno/goidc/internal/crud"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type TlsOptions struct {
	TlsAddress        string
	ServerCertificate string
	ServerKey         string
	CipherSuites      []uint16
	// The fields below will be used only if mtls is enalbed.
	MtlsAddress                    string
	CaCertificatePool              *x509.CertPool
	UnsecureCertificatesAreAllowed bool
}

type OpenIdProvider struct {
	config utils.Configuration
}

func NewProvider(
	host string,
	clientManager crud.ClientManager,
	authnSessionManager crud.AuthnSessionManager,
	grantSessionManager crud.GrantSessionManager,
	privateJwks goidc.JsonWebKeySet,
	defaultTokenKeyId string,
	defaultIdTokenKeyId string,
) *OpenIdProvider {
	provider := &OpenIdProvider{
		config: utils.Configuration{
			Host:                host,
			Profile:             goidc.OpenIdProfile,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			Scopes:              []string{string(goidc.OpenIdScope)},
			GetTokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenExpiresInSecs: goidc.DefaultTokenLifetimeSecs,
					TokenFormat:        goidc.JwtTokenFormat,
				}, nil
			},
			PrivateJwks:                   privateJwks,
			DefaultTokenSignatureKeyId:    defaultTokenKeyId,
			DefaultUserInfoSignatureKeyId: defaultIdTokenKeyId,
			UserInfoSignatureKeyIds:       []string{defaultIdTokenKeyId},
			IdTokenExpiresInSecs:          600,
			UserClaims:                    []string{},
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
			},
			ResponseTypes: []goidc.ResponseType{goidc.CodeResponse},
			ResponseModes: []goidc.ResponseMode{
				goidc.QueryResponseMode,
				goidc.FragmentResponseMode,
				goidc.FormPostResponseMode,
			},
			ClientAuthnMethods:               []goidc.ClientAuthnType{},
			DpopSignatureAlgorithms:          []jose.SignatureAlgorithm{},
			SubjectIdentifierTypes:           []goidc.SubjectIdentifierType{goidc.PublicSubjectIdentifier},
			ClaimTypes:                       []goidc.ClaimType{goidc.NormalClaimType},
			AuthenticationSessionTimeoutSecs: goidc.DefaultAuthenticationSessionTimeoutSecs,
			CorrelationIdHeader:              goidc.CorrelationIdHeader,
		},
	}

	return provider
}

func (provider *OpenIdProvider) SetSupportedUserClaims(claims ...string) {
	provider.config.UserClaims = claims
}

// Make more keys available to sign the user info endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client can choose the key to sign its ID tokens with the attribute "id_token_signed_response_alg".
func (provider *OpenIdProvider) AddUserInfoSignatureKeyIds(userInfoSignatureKeyIds ...string) {
	if !unit.ContainsAll(userInfoSignatureKeyIds, provider.config.DefaultUserInfoSignatureKeyId) {
		userInfoSignatureKeyIds = append(userInfoSignatureKeyIds, provider.config.DefaultUserInfoSignatureKeyId)
	}
	provider.config.UserInfoSignatureKeyIds = userInfoSignatureKeyIds
}

func (provider *OpenIdProvider) SetIdTokenLifetime(idTokenLifetimeSecs int) {
	provider.config.IdTokenExpiresInSecs = idTokenLifetimeSecs
}

// Enable encryption of ID tokens and of the user info endpoint response.
func (provider *OpenIdProvider) EnableUserInfoEncryption(
	keyEncryptionAlgorithms []goidc.KeyEncryptionAlgorithm,
	contentEncryptionAlgorithms []goidc.ContentEncryptionAlgorithm,
) {
	provider.config.UserInfoEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		provider.config.UserInfoKeyEncryptionAlgorithms = append(
			provider.config.UserInfoKeyEncryptionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		provider.config.UserInfoContentEncryptionAlgorithms = append(
			provider.config.UserInfoContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

// Allow clients to be registered dynamically.
func (provider *OpenIdProvider) EnableDynamicClientRegistration(
	dcrPlugin goidc.DcrPluginFunc,
	shouldRotateTokens bool,
) {
	provider.config.DcrIsEnabled = true
	provider.config.DcrPlugin = dcrPlugin
	provider.config.ShouldRotateRegistrationTokens = shouldRotateTokens

}

func (provider *OpenIdProvider) EnableRefreshTokenGrantType(
	refreshTokenLifetimeSecs int,
	shouldRotateTokens bool,
) {
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.RefreshTokenGrant)
	provider.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	provider.config.ShouldRotateRefreshTokens = shouldRotateTokens
}

func (provider *OpenIdProvider) RequireOpenIdScope() {
	provider.config.OpenIdScopeIsRequired = true
}

func (provider *OpenIdProvider) SetTokenOptions(getTokenOpts goidc.GetTokenOptionsFunc) {
	provider.config.GetTokenOptions = getTokenOpts
}

func (provider *OpenIdProvider) EnableImplicitGrantType() {
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.ImplicitGrant)
	provider.config.ResponseTypes = append(
		provider.config.ResponseTypes,
		goidc.TokenResponse,
		goidc.IdTokenResponse,
		goidc.IdTokenAndTokenResponse,
		goidc.CodeAndIdTokenResponse,
		goidc.CodeAndTokenResponse,
		goidc.CodeAndIdTokenAndTokenResponse,
	)
}

func (provider *OpenIdProvider) SetScopes(scopes ...string) {
	if slices.Contains(scopes, string(goidc.OpenIdScope)) {
		provider.config.Scopes = scopes
	} else {
		provider.config.Scopes = append(scopes, string(goidc.OpenIdScope))
	}
}

func (provider *OpenIdProvider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.config.ParLifetimeSecs = parLifetimeSecs
	provider.config.ParIsEnabled = true
}

func (provider *OpenIdProvider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.EnablePushedAuthorizationRequests(parLifetimeSecs)
	provider.config.ParIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.JarIsEnabled = true
	provider.config.JarLifetimeSecs = jarLifetimeSecs
	for _, jarAlgorithm := range jarAlgorithms {
		provider.config.JarSignatureAlgorithms = append(
			provider.config.JarSignatureAlgorithms,
			jose.SignatureAlgorithm(jarAlgorithm),
		)
	}
}

func (provider *OpenIdProvider) RequireJwtSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.EnableJwtSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
	provider.config.JarIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationRequestEncryption(
	keyEncryptionIds []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	provider.config.JarEncryptionIsEnabled = true
	provider.config.JarKeyEncryptionIds = keyEncryptionIds
	provider.config.JarContentEncryptionAlgorithms = contentEncryptionAlgorithms
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJarmSignatureKeyId string,
	jarmSignatureKeyIds ...string,
) {
	if !unit.ContainsAll(jarmSignatureKeyIds, defaultJarmSignatureKeyId) {
		jarmSignatureKeyIds = append(jarmSignatureKeyIds, defaultJarmSignatureKeyId)
	}

	provider.config.JarmIsEnabled = true
	provider.config.ResponseModes = append(
		provider.config.ResponseModes,
		goidc.JwtResponseMode,
		goidc.QueryJwtResponseMode,
		goidc.FragmentJwtResponseMode,
		goidc.FormPostJwtResponseMode,
	)
	provider.config.JarmLifetimeSecs = jarmLifetimeSecs
	provider.config.DefaultJarmSignatureKeyId = defaultJarmSignatureKeyId
	provider.config.JarmSignatureKeyIds = jarmSignatureKeyIds
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationResponseModeEncryption(
	keyEncryptionAlgorithms []goidc.KeyEncryptionAlgorithm,
	contentEncryptionAlgorithms []goidc.ContentEncryptionAlgorithm,
) {
	provider.config.JarmEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		provider.config.JarmKeyEncrytionAlgorithms = append(
			provider.config.JarmKeyEncrytionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		provider.config.JarmContentEncryptionAlgorithms = append(
			provider.config.JarmContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

func (provider *OpenIdProvider) EnableBasicSecretClientAuthn() {
	provider.config.ClientAuthnMethods = append(
		provider.config.ClientAuthnMethods,
		goidc.ClientSecretBasicAuthn,
	)
}

func (provider *OpenIdProvider) EnableSecretPostClientAuthn() {
	provider.config.ClientAuthnMethods = append(
		provider.config.ClientAuthnMethods,
		goidc.ClientSecretPostAuthn,
	)
}

func (provider *OpenIdProvider) EnablePrivateKeyJwtClientAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.PrivateKeyJwtAuthn)
	provider.config.PrivateKeyJwtAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		provider.config.PrivateKeyJwtSignatureAlgorithms = append(
			provider.config.PrivateKeyJwtSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (provider *OpenIdProvider) EnableClientSecretJwtAuthn(assertionLifetimeSecs int, signatureAlgorithms ...goidc.SignatureAlgorithm) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientSecretBasicAuthn)
	provider.config.ClientSecretJwtAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		provider.config.ClientSecretJwtSignatureAlgorithms = append(
			provider.config.ClientSecretJwtSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (provider *OpenIdProvider) EnableTlsClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.TlsAuthn)
}

func (provider *OpenIdProvider) EnableSelfSignedTlsClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.SelfSignedTlsAuthn)
}

func (provider *OpenIdProvider) EnableMtls(mtlsHost string) {
	provider.config.MtlsIsEnabled = true
	provider.config.MtlsHost = mtlsHost
}

func (provider *OpenIdProvider) EnableTlsBoundTokens() {
	provider.config.TlsBoundTokensIsEnabled = true
}

func (provider *OpenIdProvider) EnableNoneClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.NoneAuthn)
}

func (provider *OpenIdProvider) EnableIssuerResponseParameter() {
	provider.config.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableClaimsParameter() {
	provider.config.ClaimsParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableAuthorizationDetailsParameter(types ...string) {
	provider.config.AuthorizationDetailsParameterIsEnabled = true
	provider.config.AuthorizationDetailTypes = types
}

func (provider *OpenIdProvider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.DpopIsEnabled = true
	provider.config.DpopLifetimeSecs = dpopLifetimeSecs
	for _, signatureAlgorithm := range dpopSigningAlgorithms {
		provider.config.DpopSignatureAlgorithms = append(
			provider.config.DpopSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}

}

func (provider *OpenIdProvider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	provider.config.DpopIsRequired = true
}

// At least one sender constraining mechanism (TLS or DPoP) will be required, in order to issue an access token to a client.
func (provider *OpenIdProvider) RequireSenderConstrainedTokens() {
	provider.config.SenderConstrainedTokenIsRequired = true
}

func (provider *OpenIdProvider) EnableTokenIntrospection(clientAuthnMethods ...goidc.ClientAuthnType) {
	provider.config.IntrospectionIsEnabled = true
	provider.config.IntrospectionClientAuthnMethods = clientAuthnMethods
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.IntrospectionGrant)
}

func (provider *OpenIdProvider) EnableProofKeyForCodeExchange(codeChallengeMethods ...goidc.CodeChallengeMethod) {
	provider.config.CodeChallengeMethods = codeChallengeMethods
	provider.config.PkceIsEnabled = true
}

func (provider *OpenIdProvider) RequireProofKeyForCodeExchange(codeChallengeMethods ...goidc.CodeChallengeMethod) {
	provider.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	provider.config.PkceIsRequired = true
}

func (provider *OpenIdProvider) SetSupportedAuthenticationContextReferences(
	acrValues ...goidc.AuthenticationContextReference,
) {
	provider.config.AuthenticationContextReferences = acrValues
}

func (provider *OpenIdProvider) SetDisplayValuesSupported(values ...goidc.DisplayValue) {
	provider.config.DisplayValues = values
}

func (provider *OpenIdProvider) SetClaimTypesSupported(types ...goidc.ClaimType) {
	provider.config.ClaimTypes = types
}

// Set the session lifetime while the user is authenticating.
func (provider *OpenIdProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.config.AuthenticationSessionTimeoutSecs = timeoutSecs
}

func (provider *OpenIdProvider) SetCorrelationIdHeader(header string) {
	provider.config.CorrelationIdHeader = header
}

// Set the OpenId Provider profile to FAPI 2.0.
// The server will only be able to run if it is configured respecting the FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be compliant with the FAPI 2.0.
func (provider *OpenIdProvider) SetFapi2Profile() {
	provider.config.Profile = goidc.Fapi2Profile
}

func (provider *OpenIdProvider) AddClient(client models.Client) error {
	return provider.config.ClientManager.Create(context.Background(), client)
}

func (provider *OpenIdProvider) AddPolicy(policy goidc.AuthnPolicy) {
	provider.config.Policies = append(provider.config.Policies, policy)
}

func (provider *OpenIdProvider) Run(address string, middlewares ...apihandlers.WrapHandlerFunc) error {
	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	handler := provider.getServerHandler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	return http.ListenAndServe(address, handler)
}

func (provider *OpenIdProvider) RunTls(config TlsOptions, middlewares ...apihandlers.WrapHandlerFunc) error {

	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	if provider.config.MtlsIsEnabled {
		go provider.runMtls(config)
	}

	handler := provider.getServerHandler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	server := &http.Server{
		Addr:    config.TlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIdProvider) runMtls(config TlsOptions) error {

	handler := provider.getMtlsServerHandler()
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	handler = apihandlers.NewAddCertificateHeaderMiddlewareHandler(handler)

	tlsClientAuthnType := tls.RequireAndVerifyClientCert
	if config.CaCertificatePool == nil || config.UnsecureCertificatesAreAllowed {
		tlsClientAuthnType = tls.RequireAnyClientCert
	}

	server := &http.Server{
		Addr:    config.MtlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			ClientCAs:    config.CaCertificatePool,
			ClientAuth:   tlsClientAuthnType,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIdProvider) getServerHandler() http.Handler {

	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"GET "+string(goidc.JsonWebKeySetEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleJWKSRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(goidc.AuthorizationEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.AuthorizationEndpoint)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeCallbackRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.WellKnownEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleWellKnownRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.DcrIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.DynamicClientEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientCreation(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(goidc.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientUpdate(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(goidc.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientRetrieve(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(goidc.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientDelete(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}

func (provider *OpenIdProvider) getMtlsServerHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+string(goidc.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}

// TODO: Add more validations.
func (provider *OpenIdProvider) validateConfiguration() error {

	return runValidations(
		*provider,
		validateJwks,
		validateSignatureKeys,
		validateEncryptionKeys,
		validatePrivateKeyJwtSignatureAlgorithms,
		validateClientSecretJwtSignatureAlgorithms,
		validateIntrospectionClientAuthnMethods,
		validateUserInfoEncryption,
		validateJarEncryption,
		validateJarmEncryption,
		validateTokenBinding,
		validateOpenIdDefaultIdTokenSignatureAlgorithm,
		validateOpenIdDefaultJarmSignatureAlgorithm,
		validateFapi2ClientAuthnMethods,
		validateFapi2ImplicitGrantIsNotAllowed,
		validateFapi2ParIsRequired,
		validateFapi2PkceIsRequired,
		validateFapi2IssuerResponseParamIsRequired,
		validateFapi2RefreshTokenRotation,
	)
}
