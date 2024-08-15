package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage/inmemory"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *Provider)

type Provider struct {
	config oidc.Configuration
}

// New creates a new openid provider.
// By default, all clients and sessions are stored in memory and tokens are
// signed with the first signing key in the JWKS.
func New(
	issuer string,
	privateJWKS jose.JSONWebKeySet,
	opts ...ProviderOption,
) (
	*Provider,
	error,
) {

	// Use the first signature key as the default key.
	var defaultSignatureKeyID string
	for _, key := range privateJWKS.Keys {
		if key.Use == string(goidc.KeyUsageSignature) {
			defaultSignatureKeyID = key.KeyID
			break
		}
	}
	if defaultSignatureKeyID == "" {
		return nil, errors.New("the private jwks doesn't contain any signing key")
	}

	p := &Provider{
		config: oidc.Configuration{
			Host:    issuer,
			Profile: goidc.ProfileOpenID,
			Scopes:  []goidc.Scope{goidc.ScopeOpenID},
			TokenOptions: func(client *goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.NewJWTTokenOptions(defaultSignatureKeyID, defaultTokenLifetimeSecs), nil
			},
			PrivateJWKS: privateJWKS,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			SubjectIdentifierTypes:  []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
			ClaimTypes:              []goidc.ClaimType{goidc.ClaimTypeNormal},
			AuthnSessionTimeoutSecs: defaultAuthenticationSessionTimeoutSecs,
		},
	}
	p.config.Storage.Client = inmemory.NewClientManager()
	p.config.Storage.AuthnSession = inmemory.NewAuthnSessionManager()
	p.config.Storage.GrantSession = inmemory.NewGrantSessionManager()
	p.config.User.DefaultSignatureKeyID = defaultSignatureKeyID
	p.config.User.SignatureKeyIDs = []string{defaultSignatureKeyID}
	p.config.User.IDTokenExpiresInSecs = defaultIDTokenLifetimeSecs
	p.config.Endpoint.WellKnown = goidc.EndpointWellKnown
	p.config.Endpoint.JWKS = goidc.EndpointJSONWebKeySet
	p.config.Endpoint.Token = goidc.EndpointToken
	p.config.Endpoint.Authorize = goidc.EndpointAuthorize
	p.config.Endpoint.PushedAuthorization = goidc.EndpointPushedAuthorizationRequest
	p.config.Endpoint.DCR = goidc.EndpointDynamicClient
	p.config.Endpoint.UserInfo = goidc.EndpointUserInfo
	p.config.Endpoint.Introspection = goidc.EndpointTokenIntrospection

	for _, opt := range opts {
		opt(p)
	}

	if err := p.validateConfiguration(); err != nil {
		return nil, err
	}

	return p, nil
}

// Handler returns an HTTP handler with all the logic defined for the openid
// provider.
// This may be used to add the oidc logic to a HTTP server.
//
//	handler := provider.Handler()
//	server := http.NewServeMux()
//	server.Handle("/auth/*", server)
//
// TODO: Make sure it works.
func (p *Provider) Handler() http.Handler {

	server := http.NewServeMux()
	discovery.RegisterHandlers(server, &p.config)
	token.RegisterHandlers(server, &p.config)
	authorize.RegisterHandlers(server, &p.config)
	userinfo.RegisterHandlers(server, &p.config)
	client.RegisterHandlers(server, &p.config)

	return server
}

func (p *Provider) Run(
	address string,
	middlewares ...goidc.WrapHandlerFunc,
) error {
	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = newCacheControlMiddleware(handler)
	return http.ListenAndServe(address, handler)
}

func (p *Provider) RunTLS(
	config TLSOptions,
	middlewares ...goidc.WrapHandlerFunc,
) error {

	if p.config.MTLS.IsEnabled {
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
	handler = newCacheControlMiddleware(handler)
	server := &http.Server{
		Addr:    config.TLSAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

// WithStorage defines how the provider will store clients and sessions.
// It overrides the default storage which keeps everything in memory.
func WithStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) ProviderOption {
	return func(p *Provider) {
		p.config.Storage.Client = clientManager
		p.config.Storage.AuthnSession = authnSessionManager
		p.config.Storage.GrantSession = grantSessionManager
	}
}

// WithEndpointPrefix defines a shared prefix for all endpoints.
func WithEndpointPrefix(prefix string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.Prefix = prefix
	}
}

// WithEndpoints allows changing the default endpoints paths.
func WithEndpoints(
	endpointOpts struct {
		JWKS                string
		Token               string
		Authorize           string
		PushedAuthorization string
		DCR                 string
		UserInfo            string
		Introspection       string
	},
) ProviderOption {
	return func(p *Provider) {
		if endpointOpts.JWKS != "" {
			p.config.Endpoint.JWKS = endpointOpts.JWKS
		}

		if endpointOpts.Token != "" {
			p.config.Endpoint.Token = endpointOpts.Token
		}

		if endpointOpts.DCR != "" {
			p.config.Endpoint.DCR = endpointOpts.DCR
		}

		if endpointOpts.Authorize != "" {
			p.config.Endpoint.Authorize = endpointOpts.Authorize
		}

		if endpointOpts.PushedAuthorization != "" {
			p.config.Endpoint.PushedAuthorization = endpointOpts.PushedAuthorization
		}

		if endpointOpts.UserInfo != "" {
			p.config.Endpoint.UserInfo = endpointOpts.UserInfo
		}

		if endpointOpts.Introspection != "" {
			p.config.Endpoint.Introspection = endpointOpts.Introspection
		}
	}
}

// WithClaims signals support for custom user claims.
// These claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be share with the field "claims_supported" of the
// well known endpoint response.
func WithClaims(claims ...string) ProviderOption {
	return func(p *Provider) {
		p.config.Claims = claims
	}
}

func WithClaimTypes(types ...goidc.ClaimType) ProviderOption {
	return func(p *Provider) {
		p.config.ClaimTypes = types
	}
}

// WithUserInfoSignatureKeyIDs set the keys available to sign the user info
// endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be
// two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client
// can choose the key to sign its ID tokens with the attribute
// "id_token_signed_response_alg".
func WithUserInfoSignatureKeyIDs(defaultSignatureKeyID string, signatureKeyIDs ...string) ProviderOption {
	return func(p *Provider) {
		if !slices.Contains(signatureKeyIDs, defaultSignatureKeyID) {
			signatureKeyIDs = append(
				signatureKeyIDs,
				defaultSignatureKeyID,
			)
		}
		p.config.User.SignatureKeyIDs = signatureKeyIDs
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// The default is 600 seconds.
func WithIDTokenLifetime(idTokenLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.User.IDTokenExpiresInSecs = idTokenLifetimeSecs
	}
}

// WithUserInfoEncryption allows encryption of ID tokens and of the user info
// endpoint response.
func WithUserInfoEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
		p.config.User.EncryptionIsEnabled = true

		for _, keyAlg := range keyEncryptionAlgorithms {
			p.config.User.KeyEncryptionAlgorithms = append(
				p.config.User.KeyEncryptionAlgorithms,
				jose.KeyAlgorithm(keyAlg),
			)
		}

		for _, contentAlg := range contentEncryptionAlgorithms {
			p.config.User.ContentEncryptionAlgorithms = append(
				p.config.User.ContentEncryptionAlgorithms,
				jose.ContentEncryption(contentAlg),
			)
		}
	}
}

// WithDCR allows clients to be registered dynamically.
// The plugin is executed during registration and update of the client to
// perform custom validations (e.g. validate a custom property) or set default
// values (e.g. set the default scopes).
func WithDCR(
	plugin goidc.DCRPluginFunc,
	rotateTokens bool,
) ProviderOption {
	return func(p *Provider) {
		p.config.DCR.IsEnabled = true
		p.config.DCR.Plugin = plugin
		p.config.DCR.TokenRotationIsEnabled = rotateTokens
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// If true, rotateTokens will cause a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenGrant(
	refreshTokenLifetimeSecs int64,
	rotateTokens bool,
) ProviderOption {
	return func(p *Provider) {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		p.config.RefreshToken.LifetimeSecs = refreshTokenLifetimeSecs
		p.config.RefreshToken.RotationIsEnabled = rotateTokens
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all requests.
func WithOpenIDScopeRequired() ProviderOption {
	return func(p *Provider) {
		p.config.OpenIDIsRequired = true
	}
}

// WithTokenOptions defines how access tokens are issued.
func WithTokenOptions(getTokenOpts goidc.TokenOptionsFunc) ProviderOption {
	return func(p *Provider) {
		p.config.TokenOptions = func(
			client *goidc.Client,
			scopes string,
		) (
			goidc.TokenOptions,
			error,
		) {
			opts, err := getTokenOpts(client, scopes)
			if err != nil {
				return goidc.TokenOptions{}, err
			}

			if opts.OpaqueLength == token.RefreshTokenLength {
				opts.OpaqueLength++
			}

			return opts, nil
		}
	}
}

// WithImplicitGrant allows the implicit grant type and the associated
// response types.
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

// WithScopes defines the scopes accepted by the provider.
// Since the scope openid is required, it will be added in case scopes doesn't
// contain it.
func WithScopes(scopes ...goidc.Scope) ProviderOption {
	return func(p *Provider) {
		p.config.Scopes = scopes
		// The scope openid is required to be among the scopes.
		for _, scope := range scopes {
			if scope.ID == goidc.ScopeOpenID.ID {
				return
			}
		}
		p.config.Scopes = append(scopes, goidc.ScopeOpenID)
	}
}

// WithPAR allows authorization flows to start at the pushed authorization
// request endpoint.
func WithPAR(parLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.PAR.IsEnabled = true
		p.config.PAR.LifetimeSecs = parLifetimeSecs
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
func WithPARRequired(parLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		WithPAR(parLifetimeSecs)
		p.config.PAR.IsRequired = true
	}
}

// WithUnregisteredRedirectURIsDuringPAR allows clients to inform unregistered
// redirect URIs during request to pushed authorization endpoint.
// This only takes effect when PAR is enabled
func WithUnregisteredRedirectURIsDuringPAR() ProviderOption {
	return func(p *Provider) {
		p.config.PAR.AllowUnregisteredRedirectURI = true
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
func WithJAR(
	jarLifetimeSecs int64,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.JAR.IsEnabled = true
		p.config.JAR.LifetimeSecs = jarLifetimeSecs
		for _, jarAlgorithm := range jarAlgorithms {
			p.config.JAR.SignatureAlgorithms = append(
				p.config.JAR.SignatureAlgorithms,
				jose.SignatureAlgorithm(jarAlgorithm),
			)
		}
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
func WithJARRequired(
	jarLifetimeSecs int64,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithJAR(jarLifetimeSecs, jarAlgorithms...)
		p.config.JAR.IsRequired = true
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
func WithJAREncryption(
	keyEncryptionIDs []string,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
		p.config.JAR.EncryptionIsEnabled = true
		p.config.JAR.KeyEncryptionIDs = keyEncryptionIDs
		p.config.JAR.ContentEncryptionAlgorithms = contentEncryptionAlgorithms
	}
}

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// It enables JWT response modes.
func WithJARM(
	jarmLifetimeSecs int64,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) ProviderOption {
	return func(p *Provider) {
		if !slices.Contains(jarmSignatureKeyIDs, defaultJARMSignatureKeyID) {
			jarmSignatureKeyIDs = append(jarmSignatureKeyIDs, defaultJARMSignatureKeyID)
		}

		p.config.JARM.IsEnabled = true
		p.config.ResponseModes = append(
			p.config.ResponseModes,
			goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT,
			goidc.ResponseModeFragmentJWT,
			goidc.ResponseModeFormPostJWT,
		)
		p.config.JARM.LifetimeSecs = jarmLifetimeSecs
		p.config.JARM.DefaultSignatureKeyID = defaultJARMSignatureKeyID
		p.config.JARM.SignatureKeyIDs = jarmSignatureKeyIDs
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted
// JWTs.
func WithJARMEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) ProviderOption {
	return func(p *Provider) {
		p.config.JARM.EncryptionIsEnabled = true

		for _, keyAlg := range keyEncryptionAlgorithms {
			p.config.JARM.KeyEncrytionAlgorithms = append(
				p.config.JARM.KeyEncrytionAlgorithms,
				jose.KeyAlgorithm(keyAlg),
			)
		}

		for _, contentAlg := range contentEncryptionAlgorithms {
			p.config.JARM.ContentEncryptionAlgorithms = append(
				p.config.JARM.ContentEncryptionAlgorithms,
				jose.ContentEncryption(contentAlg),
			)
		}
	}
}

// WithBasicSecretAuthn allows secret basic client authentication.
func WithBasicSecretAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
	}
}

// WithBasicSecretAuthn allows secret post client authentication.
func WithSecretPostAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretPost,
		)
	}
}

// WithBasicSecretAuthn allows private key jwt client authentication.
func WithPrivateKeyJWTAuthn(
	assertionLifetimeSecs int64,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnPrivateKeyJWT,
		)
		p.config.ClientAuthn.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.ClientAuthn.PrivateKeyJWTSignatureAlgorithms = append(
				p.config.ClientAuthn.PrivateKeyJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithBasicSecretAuthn allows client secret jwt client authentication.
func WithClientSecretJWTAuthn(
	assertionLifetimeSecs int64,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
		p.config.ClientAuthn.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.ClientAuthn.ClientSecretJWTSignatureAlgorithms = append(
				p.config.ClientAuthn.ClientSecretJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithBasicSecretAuthn allows tls client authentication.
func WithTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnTLS,
		)
	}
}

// WithBasicSecretAuthn allows self signed tls client authentication.
func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSelfSignedTLS,
		)
	}
}

// WithBasicSecretAuthn allows none client authentication.
func WithNoneAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnNone,
		)
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() ProviderOption {
	return func(p *Provider) {
		p.config.IssuerResponseParameterIsEnabled = true
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() ProviderOption {
	return func(p *Provider) {
		p.config.ClaimsParameterIsEnabled = true
	}
}

// WithAuthorizationDetails allows clients to make rich authorization requests.
func WithAuthorizationDetails(types ...string) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizationDetails.IsEnabled = true
		p.config.AuthorizationDetails.Types = types
	}
}

// WithMTLS allows requests to be established with mutual TLS.
func WithMTLS(mtlsHost string, bindTokens bool) ProviderOption {
	return func(p *Provider) {
		p.config.MTLS.IsEnabled = true
		p.config.MTLS.Host = mtlsHost
		p.config.MTLS.TokenBindingIsEnabled = bindTokens
	}
}

// WithDPoP enables demonstrating proof of possesion which allows tokens to be
// bound to a cryptographic key.
func WithDPoP(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.DPoP.IsEnabled = true
		p.config.DPoP.LifetimeSecs = dpopLifetimeSecs
		for _, signatureAlgorithm := range dpopSigningAlgorithms {
			p.config.DPoP.SignatureAlgorithms = append(
				p.config.DPoP.SignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithDPoP requires tokens to be bound to a cryptographic key by demonstrating
// proof of possesion.
func WithDPoPRequired(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithDPoP(dpopLifetimeSecs, dpopSigningAlgorithms...)
		p.config.DPoP.IsRequired = true
	}
}

// WithSenderConstrainedTokensRequired will make at least one sender constraining
// mechanism (TLS or DPoP) be required, in order to issue an access token to a client.
func WithSenderConstrainedTokensRequired() ProviderOption {
	return func(p *Provider) {
		p.config.TokenBindingIsRequired = true
	}
}

// WithIntrospection allows authorized clients to introspect tokens.
func WithIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) ProviderOption {
	return func(p *Provider) {
		p.config.Introspection.IsEnabled = true
		p.config.Introspection.ClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(
			p.config.GrantTypes,
			goidc.GrantIntrospection,
		)
	}
}

// WithPKCE makes proof key for code exchange available to clients.
func WithPKCE(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *Provider) {
		p.config.PKCE.IsEnabled = true
		p.config.PKCE.CodeChallengeMethods = codeChallengeMethods
	}
}

// WithPKCERequired makes proof key for code exchange required.
func WithPKCERequired(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *Provider) {
		WithPKCE(codeChallengeMethods...)
		p.config.PKCE.IsRequired = true
	}
}

func WithACRs(
	acrValues ...goidc.ACR,
) ProviderOption {
	return func(p *Provider) {
		p.config.ACRs = acrValues
	}
}

func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *Provider) {
		p.config.DisplayValues = values
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
func WithAuthenticationSessionTimeout(timeoutSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.AuthnSessionTimeoutSecs = timeoutSecs
	}
}

// WithProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the
// FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be
// compliant with the FAPI 2.0.
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

// WithPolicy adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func WithPolicy(policy goidc.AuthnPolicy) ProviderOption {
	return func(p *Provider) {
		p.config.Policies = append(p.config.Policies, policy)
	}
}

// WithAuthorizeErrorPlugin defines a handler to be executed when the
// authorization request results in error, but the error can't be redirected.
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithAuthorizeErrorPlugin(plugin goidc.AuthorizeErrorPluginFunc) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizeErrorPlugin = plugin
	}
}

func WithResourceIndicators(resources []string) ProviderOption {
	return func(p *Provider) {
		p.config.ResourceIndicators.IsEnabled = true
		p.config.ResourceIndicators.Resources = resources
	}
}

func WithResourceIndicatorsRequired(resources []string) ProviderOption {
	return func(p *Provider) {
		WithResourceIndicators(resources)
		p.config.ResourceIndicators.IsRequired = true
	}
}

// TokenInfo returns information about the token sent in the request.
// It also validates token binding (DPoP or TLS).
func (p *Provider) TokenInfo(
	req *http.Request,
	resp http.ResponseWriter,
) goidc.TokenInfo {
	ctx := oidc.NewContext(p.config, req, resp)
	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.TokenInfo{IsActive: false}
	}

	tokenInfo := token.IntrospectionInfo(ctx, accessToken)
	confirmation := token.Confirmation{
		JWKThumbprint:               tokenInfo.JWKThumbprint,
		ClientCertificateThumbprint: tokenInfo.ClientCertificateThumbprint,
	}
	if token.ValidatePoP(ctx, accessToken, tokenType, confirmation) != nil {
		return goidc.TokenInfo{IsActive: false}
	}

	return tokenInfo
}

// Client is a shortcut to fetch client using the client storage.
func (p *Provider) Client(
	ctx context.Context,
	clientID string,
) (
	*goidc.Client,
	error,
) {
	return p.config.Storage.Client.Get(ctx, clientID)
}

func (p *Provider) runMTLS(config TLSOptions) error {

	handler := p.Handler()
	handler = newCacheControlMiddleware(handler)
	handler = newClientCertificateMiddleware(handler)

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
