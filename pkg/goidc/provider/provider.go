package provider

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *Provider)

type Provider struct {
	config oidc.Configuration
}

// New creates a new openid provider.
// By default, all clients and sessions are stored in memory and tokens are signed with the key corresponding to defaultSignatureKeyID.
func New(
	issuer string,
	privateJWKS jose.JSONWebKeySet,
	defaultSignatureKeyID string,
	opts ...ProviderOption,
) (
	*Provider,
	error,
) {
	p := &Provider{
		config: oidc.Configuration{
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

	for _, opt := range opts {
		opt(p)
	}

	if err := p.validateConfiguration(); err != nil {
		return nil, err
	}

	return p, nil
}

func WithStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientManager = clientManager
		p.config.AuthnSessionManager = authnSessionManager
		p.config.GrantSessionManager = grantSessionManager
	}
}

func WithPathPrefix(prefix string) ProviderOption {
	return func(p *Provider) {
		p.config.PathPrefix = prefix
	}
}

func WithUserClaims(claims ...string) ProviderOption {
	return func(p *Provider) {
		p.config.UserClaims = claims
	}
}

// WithUserInfoSignatureKeyIDs makes more keys available to sign the user info endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client can choose the key to sign its ID tokens with the attribute "id_token_signed_response_alg".
func WithUserInfoSignatureKeyIDs(userInfoSignatureKeyIDs ...string) ProviderOption {
	return func(p *Provider) {
		if !goidc.ContainsAll(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID) {
			userInfoSignatureKeyIDs = append(userInfoSignatureKeyIDs, p.config.DefaultUserInfoSignatureKeyID)
		}
		p.config.UserInfoSignatureKeyIDs = userInfoSignatureKeyIDs
	}
}

func WithIDTokenLifetime(idTokenLifetimeSecs int) ProviderOption {
	return func(p *Provider) {
		p.config.IDTokenExpiresInSecs = idTokenLifetimeSecs
	}
}

// WithUserInfoEncryption allows encryption of ID tokens and of the user info endpoint response.
func WithUserInfoEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
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
}

// WithDCR allows clients to be registered dynamically.
// The dcrPlugin is executed during registration and update of the client to perform
// custom validations (e.g. validate a custom property) or set default values (set the default scopes).
func WithDCR(
	dcrPlugin goidc.DCRPluginFunc,
	rotateTokens bool,
) ProviderOption {
	return func(p *Provider) {
		p.config.DCRIsEnabled = true
		p.config.DCRPlugin = dcrPlugin
		p.config.ShouldRotateRegistrationTokens = rotateTokens
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// If set to true, shouldRotateTokens will cause a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenGrant(
	refreshTokenLifetimeSecs int,
	rotateTokens bool,
) ProviderOption {
	return func(p *Provider) {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		p.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
		p.config.ShouldRotateRefreshTokens = rotateTokens
	}
}

// WithOpenIDScopeRequired forces the openid scope in all requests.
func WithOpenIDScopeRequired() ProviderOption {
	return func(p *Provider) {
		p.config.OpenIDScopeIsRequired = true
	}
}

// WithTokenOptions defines how access tokens are issued.
func WithTokenOptions(getTokenOpts goidc.TokenOptionsFunc) ProviderOption {
	return func(p *Provider) {
		p.config.TokenOptions = getTokenOpts
	}
}

// WithImplicitGrant allows the implicit grant type and the associated response types.
func WithImplicitGrant() ProviderOption {
	return func(p *Provider) {
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
}

func WithScopes(scopes ...goidc.Scope) ProviderOption {
	return func(p *Provider) {
		// The scope openid is required to be among the scopes.
		if goidc.Scopes(scopes).ContainOpenID() {
			p.config.Scopes = scopes
		} else {
			p.config.Scopes = append(scopes, goidc.ScopeOpenID)
		}
	}
}

// WithPAR allows authorization flows to start at the /par endpoint.
func WithPAR(parLifetimeSecs int) ProviderOption {
	return func(p *Provider) {
		p.config.ParLifetimeSecs = parLifetimeSecs
		p.config.PARIsEnabled = true
	}
}

// WithPARRequired forces authorization flows to start at the /par endpoint.
func WithPARRequired(parLifetimeSecs int) ProviderOption {
	return func(p *Provider) {
		WithPAR(parLifetimeSecs)
		p.config.PARIsRequired = true
	}
}

func WithJAR(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.JARIsEnabled = true
		p.config.JARLifetimeSecs = jarLifetimeSecs
		for _, jarAlgorithm := range jarAlgorithms {
			p.config.JARSignatureAlgorithms = append(
				p.config.JARSignatureAlgorithms,
				jose.SignatureAlgorithm(jarAlgorithm),
			)
		}
	}
}

// WithJARRequired makes JAR required.
func WithJARRequired(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithJAR(jarLifetimeSecs, jarAlgorithms...)
		p.config.JARIsRequired = true
	}
}

func WithJAREncryption(
	keyEncryptionIDs []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
		p.config.JAREncryptionIsEnabled = true
		p.config.JARKeyEncryptionIDs = keyEncryptionIDs
		p.config.JARContentEncryptionAlgorithms = contentEncryptionAlgorithms
	}
}

// WithJARM makes available JWT secured authorization response modes.
func WithJARM(
	jarmLifetimeSecs int,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) ProviderOption {
	return func(p *Provider) {
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
}

func WithJARMEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
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
}

func WithBasicSecretAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretBasic,
		)
	}
}

func WithSecretPostAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretPost,
		)
	}
}

func WithPrivateKeyJWTAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT)
		p.config.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.PrivateKeyJWTSignatureAlgorithms = append(
				p.config.PrivateKeyJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

func WithClientSecretJWTAuthn(
	assertionLifetimeSecs int,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSecretBasic)
		p.config.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.ClientSecretJWTSignatureAlgorithms = append(
				p.config.ClientSecretJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

func WithTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnTLS)
	}
}

func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnSelfSignedTLS)
	}
}

func WithMTLS(mtlsHost string) ProviderOption {
	return func(p *Provider) {
		p.config.MTLSIsEnabled = true
		p.config.MTLSHost = mtlsHost
	}
}

func WithTLSBoundTokens() ProviderOption {
	return func(p *Provider) {
		p.config.TLSBoundTokensIsEnabled = true
	}
}

func WithNoneAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods, goidc.ClientAuthnNone)
	}
}

func WithIssuerResponseParameter() ProviderOption {
	return func(p *Provider) {
		p.config.IssuerResponseParameterIsEnabled = true
	}
}

func WithClaimsParameter() ProviderOption {
	return func(p *Provider) {
		p.config.ClaimsParameterIsEnabled = true
	}
}

func WithAuthorizationDetails(types ...string) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizationDetailsParameterIsEnabled = true
		p.config.AuthorizationDetailTypes = types
	}
}

func WithDPoP(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.DPoPIsEnabled = true
		p.config.DPoPLifetimeSecs = dpopLifetimeSecs
		for _, signatureAlgorithm := range dpopSigningAlgorithms {
			p.config.DPoPSignatureAlgorithms = append(
				p.config.DPoPSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

func WithDPoPRequired(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithDPoP(dpopLifetimeSecs, dpopSigningAlgorithms...)
		p.config.DPoPIsRequired = true
	}
}

// WithSenderConstrainedTokensRequired will make at least one sender constraining mechanism (TLS or DPoP) be required,
// in order to issue an access token to a client.
func WithSenderConstrainedTokensRequired() ProviderOption {
	return func(p *Provider) {
		p.config.SenderConstrainedTokenIsRequired = true
	}
}

func WithIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) ProviderOption {
	return func(p *Provider) {
		p.config.IntrospectionIsEnabled = true
		p.config.IntrospectionClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
	}
}

// WithPKCE makes PKCE available to clients.
func WithPKCE(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *Provider) {
		p.config.CodeChallengeMethods = codeChallengeMethods
		p.config.PkceIsEnabled = true
	}
}

// WithPKCERequired makes PCKE required.
func WithPKCERequired(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *Provider) {
		WithPKCE(codeChallengeMethods...)
		p.config.PkceIsRequired = true
	}
}

func WithACRs(
	acrValues ...goidc.AuthenticationContextReference,
) ProviderOption {
	return func(p *Provider) {
		p.config.AuthenticationContextReferences = acrValues
	}
}

func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *Provider) {
		p.config.DisplayValues = values
	}
}

func WithClaimTypes(types ...goidc.ClaimType) ProviderOption {
	return func(p *Provider) {
		p.config.ClaimTypes = types
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
func WithAuthenticationSessionTimeout(timeoutSecs int) ProviderOption {
	return func(p *Provider) {
		p.config.AuthenticationSessionTimeoutSecs = timeoutSecs
	}
}

// WithProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be compliant with the FAPI 2.0.
func WithProfileFAPI2() ProviderOption {
	return func(p *Provider) {
		p.config.Profile = goidc.ProfileFAPI2
	}
}

// WithStaticClient adds a static client to the provider.
// The static clients are checked before consulting the client manager.
func WithStaticClient(client *goidc.Client) ProviderOption {
	return func(p *Provider) {
		p.config.StaticClients = append(p.config.StaticClients, client)
	}
}

// WithPolicy adds an authentication policy that will be evaluated at runtime and then executed if selected.
func WithPolicy(policy goidc.AuthnPolicy) ProviderOption {
	return func(p *Provider) {
		p.config.Policies = append(p.config.Policies, policy)
	}
}

// WithAuthorizeErrorPlugin defines a handler to be executed when the authorization request results in error,
// but the error can't be redirected. This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithAuthorizeErrorPlugin(plugin goidc.AuthorizeErrorPluginFunc) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizeErrorPlugin = plugin
	}
}

// TokenInfo returns information about the token sent in the request.
// It also validates token binding (DPoP or TLS).
func (p *Provider) TokenInfo(req *http.Request, resp http.ResponseWriter) goidc.TokenInfo {
	ctx := oidc.NewContext(p.config, req, resp)
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
	ctx := oidc.NewContext(p.config, req, resp)
	return p.config.ClientManager.Get(ctx, clientID)
}

func (p *Provider) Run(
	address string,
	middlewares ...WrapHandlerFunc,
) error {

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
