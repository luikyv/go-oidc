package goidcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/apihandlers"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type TLSOptions struct {
	TLSAddress        string
	ServerCertificate string
	ServerKey         string
	CipherSuites      []uint16
	// The fields below will be used only if mtls is enalbed.
	MTLSAddress                    string
	CaCertificatePool              *x509.CertPool
	UnsecureCertificatesAreAllowed bool
}

type OpenIDProvider struct {
	config utils.Configuration
}

func NewProvider(
	host string,
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
	privateJWKS goidc.JSONWebKeySet,
	defaultTokenKeyID string,
	defaultIDTokenKeyID string,
) *OpenIDProvider {
	provider := &OpenIDProvider{
		config: utils.Configuration{
			Host:                host,
			Profile:             goidc.ProfileOpenID,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			OAuthScopes:         []goidc.Scope{goidc.ScopeOpenID},
			TokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenLifetimeSecs: goidc.DefaultTokenLifetimeSecs,
					TokenFormat:       goidc.TokenFormatJWT,
				}, nil
			},
			PrivateJWKS:                   privateJWKS,
			DefaultTokenSignatureKeyID:    defaultTokenKeyID,
			DefaultUserInfoSignatureKeyID: defaultIDTokenKeyID,
			UserInfoSignatureKeyIDs:       []string{defaultIDTokenKeyID},
			IDTokenExpiresInSecs:          600,
			UserClaims:                    []string{},
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			ClientAuthnMethods:               []goidc.ClientAuthnType{},
			DPOPSignatureAlgorithms:          []jose.SignatureAlgorithm{},
			SubjectIdentifierTypes:           []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
			ClaimTypes:                       []goidc.ClaimType{goidc.ClaimTypeNormal},
			AuthenticationSessionTimeoutSecs: goidc.DefaultAuthenticationSessionTimeoutSecs,
			CorrelationIDHeader:              goidc.HeaderCorrelationID,
		},
	}

	return provider
}

func (provider *OpenIDProvider) SetSupportedUserClaims(claims ...string) {
	provider.config.UserClaims = claims
}

// AddUserInfoSignatureKeyIDs makes more keys available to sign the user info endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client can choose the key to sign its ID tokens with the attribute "id_token_signed_response_alg".
func (provider *OpenIDProvider) AddUserInfoSignatureKeyIDs(userInfoSignatureKeyIDs ...string) {
	if !goidc.ContainsAll(userInfoSignatureKeyIDs, provider.config.DefaultUserInfoSignatureKeyID) {
		userInfoSignatureKeyIDs = append(userInfoSignatureKeyIDs, provider.config.DefaultUserInfoSignatureKeyID)
	}
	provider.config.UserInfoSignatureKeyIDs = userInfoSignatureKeyIDs
}

func (provider *OpenIDProvider) SetIDTokenLifetime(idTokenLifetimeSecs int) {
	provider.config.IDTokenExpiresInSecs = idTokenLifetimeSecs
}

// EnableUserInfoEncryption allows encryption of ID tokens and of the user info endpoint response.
func (provider *OpenIDProvider) EnableUserInfoEncryption(
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

// EnableDynamicClientRegistration allows clients to be registered dynamically.
// The dcrPlugin is executed during registration and update of the client to perform
// custom validations (e.g. validate a custom property) or set default values (set the default scopes).
func (provider *OpenIDProvider) EnableDynamicClientRegistration(
	dcrPlugin goidc.DCRPluginFunc,
	shouldRotateTokens bool,
) {
	provider.config.DCRIsEnabled = true
	provider.config.DCRPlugin = dcrPlugin
	provider.config.ShouldRotateRegistrationTokens = shouldRotateTokens

}

// EnableRefreshTokenGrantType makes available the refresh token grant.
// If set to true, shouldRotateTokens will cause a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func (provider *OpenIDProvider) EnableRefreshTokenGrantType(
	refreshTokenLifetimeSecs int,
	shouldRotateTokens bool,
) {
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.GrantRefreshToken)
	provider.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	provider.config.ShouldRotateRefreshTokens = shouldRotateTokens
}

// RequireOpenIDScope forces the openid scope in all requests.
func (provider *OpenIDProvider) RequireOpenIDScope() {
	provider.config.OpenIDScopeIsRequired = true
}

// SetTokenOptions defines how access tokens are issued.
func (provider *OpenIDProvider) SetTokenOptions(getTokenOpts goidc.TokenOptionsFunc) {
	provider.config.TokenOptions = getTokenOpts
}

// EnableImplicitGrantType allows the implicit grant type and the associated response types.
func (provider *OpenIDProvider) EnableImplicitGrantType() {
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.GrantImplicit)
	provider.config.ResponseTypes = append(
		provider.config.ResponseTypes,
		goidc.ResponseTypeToken,
		goidc.ResponseTypeIDToken,
		goidc.ResponseTypeIDTokenAndToken,
		goidc.ResponseTypeCodeAndIDToken,
		goidc.ResponseTypeCodeAndToken,
		goidc.ResponseTypeCodeAndIDTokenAndToken,
	)
}

func (provider *OpenIDProvider) SetScopes(scopes ...goidc.Scope) {
	// The scope openid is required to be among the scopes.
	if goidc.Scopes(scopes).ContainsOpenID() {
		provider.config.OAuthScopes = scopes
	} else {
		provider.config.OAuthScopes = append(scopes, goidc.ScopeOpenID)
	}
}

// EnablePushedAuthorizationRequests allows authorization flows to start at the /par endpoint.
func (provider *OpenIDProvider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.config.ParLifetimeSecs = parLifetimeSecs
	provider.config.PARIsEnabled = true
}

// RequirePushedAuthorizationRequests forces authorization flows to start at the /par endpoint.
func (provider *OpenIDProvider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.EnablePushedAuthorizationRequests(parLifetimeSecs)
	provider.config.PARIsRequired = true
}

func (provider *OpenIDProvider) EnableJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.JARIsEnabled = true
	provider.config.JARLifetimeSecs = jarLifetimeSecs
	for _, jarAlgorithm := range jarAlgorithms {
		provider.config.JARSignatureAlgorithms = append(
			provider.config.JARSignatureAlgorithms,
			jose.SignatureAlgorithm(jarAlgorithm),
		)
	}
}

// RequireJWTSecuredAuthorizationRequests makes JAR required.
func (provider *OpenIDProvider) RequireJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.EnableJWTSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
	provider.config.JARIsRequired = true
}

func (provider *OpenIDProvider) EnableJWTSecuredAuthorizationRequestEncryption(
	keyEncryptionIDs []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	provider.config.JAREncryptionIsEnabled = true
	provider.config.JARKeyEncryptionIDs = keyEncryptionIDs
	provider.config.JARContentEncryptionAlgorithms = contentEncryptionAlgorithms
}

// EnableJWTSecuredAuthorizationResponseMode makes available JARM and the associated response modes.
func (provider *OpenIDProvider) EnableJWTSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) {
	if !goidc.ContainsAll(jarmSignatureKeyIDs, defaultJARMSignatureKeyID) {
		jarmSignatureKeyIDs = append(jarmSignatureKeyIDs, defaultJARMSignatureKeyID)
	}

	provider.config.JARMIsEnabled = true
	provider.config.ResponseModes = append(
		provider.config.ResponseModes,
		goidc.ResponseModeJWT,
		goidc.ResponseModeQueryJWT,
		goidc.ResponseModeFragmentJWT,
		goidc.ResponseModeFormPostJWT,
	)
	provider.config.JARMLifetimeSecs = jarmLifetimeSecs
	provider.config.DefaultJARMSignatureKeyID = defaultJARMSignatureKeyID
	provider.config.JARMSignatureKeyIDs = jarmSignatureKeyIDs
}

func (provider *OpenIDProvider) EnableJWTSecuredAuthorizationResponseModeEncryption(
	keyEncryptionAlgorithms []goidc.KeyEncryptionAlgorithm,
	contentEncryptionAlgorithms []goidc.ContentEncryptionAlgorithm,
) {
	provider.config.JARMEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		provider.config.JARMKeyEncrytionAlgorithms = append(
			provider.config.JARMKeyEncrytionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		provider.config.JARMContentEncryptionAlgorithms = append(
			provider.config.JARMContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

func (provider *OpenIDProvider) EnableBasicSecretClientAuthn() {
	provider.config.ClientAuthnMethods = append(
		provider.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretBasic,
	)
}

func (provider *OpenIDProvider) EnableSecretPostClientAuthn() {
	provider.config.ClientAuthnMethods = append(
		provider.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretPost,
	)
}

func (provider *OpenIDProvider) EnablePrivateKeyJWTClientAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT)
	provider.config.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		provider.config.PrivateKeyJWTSignatureAlgorithms = append(
			provider.config.PrivateKeyJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (provider *OpenIDProvider) EnableClientSecretJWTAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientAuthnSecretBasic)
	provider.config.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		provider.config.ClientSecretJWTSignatureAlgorithms = append(
			provider.config.ClientSecretJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (provider *OpenIDProvider) EnableTLSClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientAuthnTLS)
}

func (provider *OpenIDProvider) EnableSelfSignedTLSClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientAuthnSelfSignedTLS)
}

func (provider *OpenIDProvider) EnableMTLS(mtlsHost string) {
	provider.config.MTLSIsEnabled = true
	provider.config.MTLSHost = mtlsHost
}

func (provider *OpenIDProvider) EnableTLSBoundTokens() {
	provider.config.TLSBoundTokensIsEnabled = true
}

func (provider *OpenIDProvider) EnableNoneClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, goidc.ClientAuthnNone)
}

func (provider *OpenIDProvider) EnableIssuerResponseParameter() {
	provider.config.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIDProvider) EnableClaimsParameter() {
	provider.config.ClaimsParameterIsEnabled = true
}

func (provider *OpenIDProvider) EnableAuthorizationDetailsParameter(types ...string) {
	provider.config.AuthorizationDetailsParameterIsEnabled = true
	provider.config.AuthorizationDetailTypes = types
}

func (provider *OpenIDProvider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.config.DPOPIsEnabled = true
	provider.config.DPOPLifetimeSecs = dpopLifetimeSecs
	for _, signatureAlgorithm := range dpopSigningAlgorithms {
		provider.config.DPOPSignatureAlgorithms = append(
			provider.config.DPOPSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}

}

func (provider *OpenIDProvider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...goidc.SignatureAlgorithm,
) {
	provider.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	provider.config.DPOPIsRequired = true
}

// RequireSenderConstrainedTokens will make at least one sender constraining mechanism (TLS or DPoP) be required,
// in order to issue an access token to a client.
func (provider *OpenIDProvider) RequireSenderConstrainedTokens() {
	provider.config.SenderConstrainedTokenIsRequired = true
}

func (provider *OpenIDProvider) EnableTokenIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) {
	provider.config.IntrospectionIsEnabled = true
	provider.config.IntrospectionClientAuthnMethods = clientAuthnMethods
	provider.config.GrantTypes = append(provider.config.GrantTypes, goidc.GrantIntrospection)
}

// EnableProofKeyForCodeExchange makes PKCE available to clients.
func (provider *OpenIDProvider) EnableProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	provider.config.CodeChallengeMethods = codeChallengeMethods
	provider.config.PkceIsEnabled = true
}

// RequireProofKeyForCodeExchange makes PCKE required.
func (provider *OpenIDProvider) RequireProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	provider.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	provider.config.PkceIsRequired = true
}

func (provider *OpenIDProvider) SetSupportedAuthenticationContextReferences(
	acrValues ...goidc.AuthenticationContextReference,
) {
	provider.config.AuthenticationContextReferences = acrValues
}

func (provider *OpenIDProvider) SetDisplayValuesSupported(values ...goidc.DisplayValue) {
	provider.config.DisplayValues = values
}

func (provider *OpenIDProvider) SetClaimTypesSupported(types ...goidc.ClaimType) {
	provider.config.ClaimTypes = types
}

// SetAuthenticationSessionTimeout sets the user authentication session lifetime.
func (provider *OpenIDProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.config.AuthenticationSessionTimeoutSecs = timeoutSecs
}

// SetHeaderCorrelationID sets the header expected to have the correlation ID that will be used for all requests to the server.
func (provider *OpenIDProvider) SetHeaderCorrelationID(header string) {
	provider.config.CorrelationIDHeader = header
}

// SetProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be compliant with the FAPI 2.0.
func (provider *OpenIDProvider) SetProfileFAPI2() {
	provider.config.Profile = goidc.ProfileFAPI2
}

// AddClient creates or updates a static client.
func (provider *OpenIDProvider) AddClient(client goidc.Client) error {
	return provider.config.ClientManager.CreateOrUpdate(context.Background(), client)
}

// AddPolicy adds an authentication policy that will be evaluated at runtime and then executed if selected.
func (provider *OpenIDProvider) AddPolicy(policy goidc.AuthnPolicy) {
	provider.config.Policies = append(provider.config.Policies, policy)
}

func (provider *OpenIDProvider) Run(
	address string,
	middlewares ...apihandlers.WrapHandlerFunc,
) error {
	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	handler := provider.getServerHandler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = apihandlers.NewAddCorrelationIDHeaderMiddlewareHandler(handler, provider.config.CorrelationIDHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	return http.ListenAndServe(address, handler)
}

func (provider *OpenIDProvider) RunTLS(
	config TLSOptions,
	middlewares ...apihandlers.WrapHandlerFunc,
) error {

	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	if provider.config.MTLSIsEnabled {
		go func() {
			if err := provider.runMTLS(config); err != nil {
				// TODO: Find a way to handle this.
				panic(err)
			}
		}()
	}

	handler := provider.getServerHandler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = apihandlers.NewAddCorrelationIDHeaderMiddlewareHandler(handler, provider.config.CorrelationIDHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	server := &http.Server{
		Addr:    config.TLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIDProvider) runMTLS(config TLSOptions) error {

	handler := provider.getMTLSServerHandler()
	handler = apihandlers.NewAddCorrelationIDHeaderMiddlewareHandler(handler, provider.config.CorrelationIDHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	handler = apihandlers.NewAddCertificateHeaderMiddlewareHandler(handler)

	tlsClientAuthnType := tls.RequireAndVerifyClientCert
	if config.CaCertificatePool == nil || config.UnsecureCertificatesAreAllowed {
		tlsClientAuthnType = tls.RequireAnyClientCert
	}

	server := &http.Server{
		Addr:    config.MTLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			ClientCAs:    config.CaCertificatePool,
			ClientAuth:   tlsClientAuthnType,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIDProvider) getServerHandler() http.Handler {

	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointJSONWebKeySet),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleJWKSRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.PARIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointPushedAuthorizationRequest),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointAuthorization),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointAuthorization)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeCallbackRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointToken),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointWellKnown),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleWellKnownRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.DCRIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointDynamicClient),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientCreation(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientUpdate(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientRetrieve(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(goidc.EndpointDynamicClient)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientDelete(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointTokenIntrospection),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}

func (provider *OpenIDProvider) getMTLSServerHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointToken),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(goidc.EndpointUserInfo),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.PARIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointPushedAuthorizationRequest),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(goidc.EndpointTokenIntrospection),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}

// TODO: Add more validations.
func (provider *OpenIDProvider) validateConfiguration() error {

	return runValidations(
		*provider,
		validateJWKS,
		validateSignatureKeys,
		validateEncryptionKeys,
		validatePrivateKeyJWTSignatureAlgorithms,
		validateClientSecretJWTSignatureAlgorithms,
		validateIntrospectionClientAuthnMethods,
		validateUserInfoEncryption,
		validateJAREncryption,
		validateJARMEncryption,
		validateTokenBinding,
		validateOpenIDDefaultIDTokenSignatureAlgorithm,
		validateOpenIDDefaultJARMSignatureAlgorithm,
		validateFAPI2ClientAuthnMethods,
		validateFAPI2ImplicitGrantIsNotAllowed,
		validateFAPI2PARIsRequired,
		validateFAPI2PkceIsRequired,
		validateFAPI2IssuerResponseParamIsRequired,
		validateFAPI2RefreshTokenRotation,
	)
}
