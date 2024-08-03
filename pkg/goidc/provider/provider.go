package provider

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Provider struct {
	config utils.Configuration
}

// New creates a new openid provider.
// By default, all clients and sessions are stored in memory and tokens are signed with the key corresponding to defaultSignatureKeyID.
func New(
	issuer string,
	privateJWKS jose.JSONWebKeySet,
	defaultSignatureKeyID string,
) *Provider {
	p := &Provider{
		config: utils.Configuration{
			Host:                issuer,
			Profile:             goidc.ProfileOpenID,
			ClientManager:       NewInMemoryClientManager(),
			AuthnSessionManager: NewInMemoryAuthnSessionManager(),
			GrantSessionManager: NewInMemoryGrantSessionManager(),
			Scopes:              []goidc.Scope{goidc.ScopeOpenID},
			TokenOptions: func(client *goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.NewJWTTokenOptions(defaultSignatureKeyID, goidc.DefaultTokenLifetimeSecs), nil
			},
			PrivateJWKS:                   privateJWKS,
			DefaultTokenSignatureKeyID:    defaultSignatureKeyID,
			DefaultUserInfoSignatureKeyID: defaultSignatureKeyID,
			UserInfoSignatureKeyIDs:       []string{defaultSignatureKeyID},
			IDTokenExpiresInSecs:          goidc.DefaultIDTokenLifetimeSecs,
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
			SubjectIdentifierTypes:           []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
			ClaimTypes:                       []goidc.ClaimType{goidc.ClaimTypeNormal},
			AuthenticationSessionTimeoutSecs: goidc.DefaultAuthenticationSessionTimeoutSecs,
		},
	}

	return p
}

func (p *Provider) SetStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) {
	p.config.ClientManager = clientManager
	p.config.AuthnSessionManager = authnSessionManager
	p.config.GrantSessionManager = grantSessionManager
}

func (p *Provider) SetPathPrefix(prefix string) {
	p.config.PathPrefix = prefix
}

func (p *Provider) SetSupportedUserClaims(claims ...string) {
	p.config.UserClaims = claims
}

// AddUserInfoSignatureKeyIDs makes more keys available to sign the user info endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client can choose the key to sign its ID tokens with the attribute "id_token_signed_response_alg".
func (p *Provider) AddUserInfoSignatureKeyIDs(userInfoSignatureKeyIDs ...string) {
	if !goidc.ContainsAll(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID) {
		userInfoSignatureKeyIDs = append(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID)
	}
	p.config.UserInfoSignatureKeyIDs = userInfoSignatureKeyIDs
}

func (p *Provider) SetIDTokenLifetime(idTokenLifetimeSecs int) {
	p.config.IDTokenExpiresInSecs = idTokenLifetimeSecs
}

// EnableUserInfoEncryption allows encryption of ID tokens and of the user info endpoint response.
func (p *Provider) EnableUserInfoEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	p.config.UserInfoEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		p.config.UserInfoKeyEncryptionAlgorithms = append(
			p.config.UserInfoKeyEncryptionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		p.config.UserInfoContentEncryptionAlgorithms = append(
			p.config.UserInfoContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

// EnableDynamicClientRegistration allows clients to be registered dynamically.
// The dcrPlugin is executed during registration and update of the client to perform
// custom validations (e.g. validate a custom property) or set default values (set the default scopes).
func (p *Provider) EnableDynamicClientRegistration(
	dcrPlugin goidc.DCRPluginFunc,
	shouldRotateTokens bool,
) {
	p.config.DCRIsEnabled = true
	p.config.DCRPlugin = dcrPlugin
	p.config.ShouldRotateRegistrationTokens = shouldRotateTokens

}

// EnableRefreshTokenGrantType makes available the refresh token grant.
// If set to true, shouldRotateTokens will cause a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func (p *Provider) EnableRefreshTokenGrantType(
	refreshTokenLifetimeSecs int,
	shouldRotateTokens bool,
) {
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
	p.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	p.config.ShouldRotateRefreshTokens = shouldRotateTokens
}

// RequireOpenIDScope forces the openid scope in all requests.
func (p *Provider) RequireOpenIDScope() {
	p.config.OpenIDScopeIsRequired = true
}

// SetTokenOptions defines how access tokens are issued.
func (p *Provider) SetTokenOptions(getTokenOpts goidc.TokenOptionsFunc) {
	p.config.TokenOptions = getTokenOpts
}

// EnableImplicitGrantType allows the implicit grant type and the associated response types.
func (p *Provider) EnableImplicitGrantType() {
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantImplicit)
	p.config.ResponseTypes = append(
		p.config.ResponseTypes,
		goidc.ResponseTypeToken,
		goidc.ResponseTypeIDToken,
		goidc.ResponseTypeIDTokenAndToken,
		goidc.ResponseTypeCodeAndIDToken,
		goidc.ResponseTypeCodeAndToken,
		goidc.ResponseTypeCodeAndIDTokenAndToken,
	)
}

func (p *Provider) SetScopes(scopes ...goidc.Scope) {
	// The scope openid is required to be among the scopes.
	if goidc.Scopes(scopes).ContainOpenID() {
		p.config.Scopes = scopes
	} else {
		p.config.Scopes = append(scopes, goidc.ScopeOpenID)
	}
}

// EnablePushedAuthorizationRequests allows authorization flows to start at the /par endpoint.
func (p *Provider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	p.config.ParLifetimeSecs = parLifetimeSecs
	p.config.PARIsEnabled = true
}

// RequirePushedAuthorizationRequests forces authorization flows to start at the /par endpoint.
func (p *Provider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	p.EnablePushedAuthorizationRequests(parLifetimeSecs)
	p.config.PARIsRequired = true
}

func (p *Provider) EnableJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	p.config.JARIsEnabled = true
	p.config.JARLifetimeSecs = jarLifetimeSecs
	for _, jarAlgorithm := range jarAlgorithms {
		p.config.JARSignatureAlgorithms = append(
			p.config.JARSignatureAlgorithms,
			jose.SignatureAlgorithm(jarAlgorithm),
		)
	}
}

// RequireJWTSecuredAuthorizationRequests makes JAR required.
func (p *Provider) RequireJWTSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	p.EnableJWTSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
	p.config.JARIsRequired = true
}

func (p *Provider) EnableJWTSecuredAuthorizationRequestEncryption(
	keyEncryptionIDs []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	p.config.JAREncryptionIsEnabled = true
	p.config.JARKeyEncryptionIDs = keyEncryptionIDs
	p.config.JARContentEncryptionAlgorithms = contentEncryptionAlgorithms
}

// EnableJWTSecuredAuthorizationResponseMode makes available JARM and the associated response modes.
func (p *Provider) EnableJWTSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) {
	if !goidc.ContainsAll(jarmSignatureKeyIDs, defaultJARMSignatureKeyID) {
		jarmSignatureKeyIDs = append(jarmSignatureKeyIDs, defaultJARMSignatureKeyID)
	}

	p.config.JARMIsEnabled = true
	p.config.ResponseModes = append(
		p.config.ResponseModes,
		goidc.ResponseModeJWT,
		goidc.ResponseModeQueryJWT,
		goidc.ResponseModeFragmentJWT,
		goidc.ResponseModeFormPostJWT,
	)
	p.config.JARMLifetimeSecs = jarmLifetimeSecs
	p.config.DefaultJARMSignatureKeyID = defaultJARMSignatureKeyID
	p.config.JARMSignatureKeyIDs = jarmSignatureKeyIDs
}

func (p *Provider) EnableJWTSecuredAuthorizationResponseModeEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	p.config.JARMEncryptionIsEnabled = true

	for _, keyAlg := range keyEncryptionAlgorithms {
		p.config.JARMKeyEncrytionAlgorithms = append(
			p.config.JARMKeyEncrytionAlgorithms,
			jose.KeyAlgorithm(keyAlg),
		)
	}

	for _, contentAlg := range contentEncryptionAlgorithms {
		p.config.JARMContentEncryptionAlgorithms = append(
			p.config.JARMContentEncryptionAlgorithms,
			jose.ContentEncryption(contentAlg),
		)
	}
}

func (p *Provider) EnableBasicSecretClientAuthn() {
	p.config.ClientAuthnMethods = append(
		p.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretBasic,
	)
}

func (p *Provider) EnableSecretPostClientAuthn() {
	p.config.ClientAuthnMethods = append(
		p.config.ClientAuthnMethods,
		goidc.ClientAuthnSecretPost,
	)
}

func (p *Provider) EnablePrivateKeyJWTClientAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT)
	p.config.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		p.config.PrivateKeyJWTSignatureAlgorithms = append(
			p.config.PrivateKeyJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (p *Provider) EnableClientSecretJWTAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSecretBasic)
	p.config.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
	for _, signatureAlgorithm := range signatureAlgorithms {
		p.config.ClientSecretJWTSignatureAlgorithms = append(
			p.config.ClientSecretJWTSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (p *Provider) EnableTLSClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnTLS)
}

func (p *Provider) EnableSelfSignedTLSClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSelfSignedTLS)
}

func (p *Provider) EnableMTLS(mtlsHost string) {
	p.config.MTLSIsEnabled = true
	p.config.MTLSHost = mtlsHost
}

func (p *Provider) EnableTLSBoundTokens() {
	p.config.TLSBoundTokensIsEnabled = true
}

func (p *Provider) EnableNoneClientAuthn() {
	p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnNone)
}

func (p *Provider) EnableIssuerResponseParameter() {
	p.config.IssuerResponseParameterIsEnabled = true
}

func (p *Provider) EnableClaimsParameter() {
	p.config.ClaimsParameterIsEnabled = true
}

func (p *Provider) EnableAuthorizationDetailsParameter(types ...string) {
	p.config.AuthorizationDetailsParameterIsEnabled = true
	p.config.AuthorizationDetailTypes = types
}

func (p *Provider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	p.config.DPoPIsEnabled = true
	p.config.DPoPLifetimeSecs = dpopLifetimeSecs
	for _, signatureAlgorithm := range dpopSigningAlgorithms {
		p.config.DPoPSignatureAlgorithms = append(
			p.config.DPoPSignatureAlgorithms,
			jose.SignatureAlgorithm(signatureAlgorithm),
		)
	}
}

func (p *Provider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	p.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	p.config.DPoPIsRequired = true
}

// RequireSenderConstrainedTokens will make at least one sender constraining mechanism (TLS or DPoP) be required,
// in order to issue an access token to a client.
func (p *Provider) RequireSenderConstrainedTokens() {
	p.config.SenderConstrainedTokenIsRequired = true
}

func (p *Provider) EnableTokenIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) {
	p.config.IntrospectionIsEnabled = true
	p.config.IntrospectionClientAuthnMethods = clientAuthnMethods
	p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
}

// EnableProofKeyForCodeExchange makes PKCE available to clients.
func (p *Provider) EnableProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	p.config.CodeChallengeMethods = codeChallengeMethods
	p.config.PkceIsEnabled = true
}

// RequireProofKeyForCodeExchange makes PCKE required.
func (p *Provider) RequireProofKeyForCodeExchange(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) {
	p.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	p.config.PkceIsRequired = true
}

func (p *Provider) SetSupportedAuthenticationContextReferences(
	acrValues ...goidc.AuthenticationContextReference,
) {
	p.config.AuthenticationContextReferences = acrValues
}

func (p *Provider) SetDisplayValuesSupported(values ...goidc.DisplayValue) {
	p.config.DisplayValues = values
}

func (p *Provider) SetClaimTypesSupported(types ...goidc.ClaimType) {
	p.config.ClaimTypes = types
}

// SetAuthenticationSessionTimeout sets the user authentication session lifetime.
func (p *Provider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	p.config.AuthenticationSessionTimeoutSecs = timeoutSecs
}

// SetProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be compliant with the FAPI 2.0.
func (p *Provider) SetProfileFAPI2() {
	p.config.Profile = goidc.ProfileFAPI2
}

// AddClient adds a static client to the provider.
// The static clients are checked before consulting the client manager.
func (p *Provider) AddClient(client *goidc.Client) {
	p.config.StaticClients = append(p.config.StaticClients, client)
}

// AddPolicy adds an authentication policy that will be evaluated at runtime and then executed if selected.
func (p *Provider) AddPolicy(policy goidc.AuthnPolicy) {
	p.config.Policies = append(p.config.Policies, policy)
}

// SetAuthorizeErrorPlugin defines a handler to be executed when the authorization request results in error,
// but the error can't be redirected. This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func (p *Provider) SetAuthorizeErrorPlugin(plugin goidc.AuthorizeErrorPluginFunc) {
	p.config.AuthorizeErrorPlugin = plugin
}

// TokenInfo returns information about the token sent in the request.
// It also validates token binding (DPoP or TLS).
func (p *Provider) TokenInfo(req *http.Request, resp http.ResponseWriter) goidc.TokenInfo {
	ctx := utils.NewContext(p.config, req, resp)
	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.NewInactiveTokenInfo()
	}

	tokenInfo := token.TokenIntrospectionInfo(ctx, accessToken)
	if token.ValidatePoP(ctx, accessToken, tokenType, tokenInfo.Confirmation()) != nil {
		return goidc.NewInactiveTokenInfo()
	}

	return tokenInfo
}

func (p *Provider) Client(req *http.Request, resp http.ResponseWriter, clientID string) (*goidc.Client, error) {
	ctx := utils.NewContext(p.config, req, resp)
	return p.config.ClientManager.Get(ctx, clientID)
}

func (p *Provider) Run(
	address string,
	middlewares ...WrapHandlerFunc,
) error {
	if err := p.validateConfiguration(); err != nil {
		return err
	}

	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = NewCacheControlMiddleware(handler)
	return http.ListenAndServe(address, handler)
}

func (p *Provider) RunTLS(
	config TLSOptions,
	middlewares ...WrapHandlerFunc,
) error {

	if err := p.validateConfiguration(); err != nil {
		return err
	}

	if p.config.MTLSIsEnabled {
		go func() {
			if err := p.runMTLS(config); err != nil {
				// TODO: Find a way to handle this.
				panic(err)
			}
		}()
	}

	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = NewCacheControlMiddleware(handler)
	server := &http.Server{
		Addr:    config.TLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (p *Provider) runMTLS(config TLSOptions) error {

	handler := p.mtlsHandler()
	handler = NewCacheControlMiddleware(handler)
	handler = NewClientCertificateMiddleware(handler)

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

func (p *Provider) Handler() http.Handler {

	handler := http.NewServeMux()

	handler.HandleFunc(
		"GET "+p.config.PathPrefix+string(goidc.EndpointJSONWebKeySet),
		discovery.HandlerJWKS(&p.config),
	)

	if p.config.PARIsEnabled {
		handler.HandleFunc(
			"POST "+p.config.PathPrefix+string(goidc.EndpointPushedAuthorizationRequest),
			authorize.HandlerPush(&p.config),
		)
	}

	handler.HandleFunc(
		"GET "+p.config.PathPrefix+string(goidc.EndpointAuthorization),
		authorize.Handler(&p.config),
	)

	handler.HandleFunc(
		"POST "+p.config.PathPrefix+string(goidc.EndpointAuthorization)+"/{callback}",
		authorize.HandlerCallback(&p.config),
	)

	handler.HandleFunc(
		"POST "+p.config.PathPrefix+string(goidc.EndpointToken),
		token.Handler(&p.config),
	)

	handler.HandleFunc(
		"GET "+p.config.PathPrefix+string(goidc.EndpointWellKnown),
		discovery.HandlerWellKnown(&p.config),
	)

	handler.HandleFunc(
		"GET "+p.config.PathPrefix+string(goidc.EndpointUserInfo),
		userinfo.Handler(&p.config),
	)

	handler.HandleFunc(
		"POST "+p.config.PathPrefix+string(goidc.EndpointUserInfo),
		userinfo.Handler(&p.config),
	)

	if p.config.DCRIsEnabled {
		handler.HandleFunc(
			"POST "+p.config.PathPrefix+string(goidc.EndpointDynamicClient),
			dcr.HandlerCreate(p.config),
		)

		handler.HandleFunc(
			"PUT "+p.config.PathPrefix+string(goidc.EndpointDynamicClient)+"/{client_id}",
			dcr.HandlerUpdate(p.config),
		)

		handler.HandleFunc(
			"GET "+p.config.PathPrefix+string(goidc.EndpointDynamicClient)+"/{client_id}",
			dcr.HandlerGet(p.config),
		)

		handler.HandleFunc(
			"DELETE "+p.config.PathPrefix+string(goidc.EndpointDynamicClient)+"/{client_id}",
			dcr.HandlerDelete(p.config),
		)
	}

	if p.config.IntrospectionIsEnabled {
		handler.HandleFunc(
			"POST "+p.config.PathPrefix+string(goidc.EndpointTokenIntrospection),
			token.HandlerIntrospect(&p.config),
		)
	}

	return handler
}

func (p *Provider) mtlsHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+p.config.PathPrefix+string(goidc.EndpointToken),
		token.Handler(&p.config),
	)

	serverHandler.HandleFunc(
		"GET "+p.config.PathPrefix+string(goidc.EndpointUserInfo),
		userinfo.Handler(&p.config),
	)

	serverHandler.HandleFunc(
		"POST "+p.config.PathPrefix+string(goidc.EndpointUserInfo),
		userinfo.Handler(&p.config),
	)

	if p.config.PARIsEnabled {
		serverHandler.HandleFunc(
			"POST "+p.config.PathPrefix+string(goidc.EndpointPushedAuthorizationRequest),
			authorize.HandlerPush(&p.config),
		)
	}

	if p.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+p.config.PathPrefix+string(goidc.EndpointTokenIntrospection),
			token.HandlerIntrospect(&p.config),
		)
	}

	return serverHandler
}

// TODO: Add more validations.
func (p *Provider) validateConfiguration() error {

	return runValidations(
		*p,
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
		validateOpenIDProfile,
		validateFAPI2Profile,
	)
}

type TLSOptions struct {
	TLSAddress                     string
	ServerCertificate              string
	ServerKey                      string
	CipherSuites                   []uint16
	MTLSAddress                    string
	CaCertificatePool              *x509.CertPool
	UnsecureCertificatesAreAllowed bool
}
