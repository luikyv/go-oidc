package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Provider struct {
	config *oidc.Configuration
}

// New creates a new openid provider.
// By default, all clients and sessions are stored in memory and JWTs are
// signed with the first signing key in the JWKS.
// The profile parameter adjusts the server's behavior for non-configurable
// settings, ensuring compliance with the associated specification. Depending on
// the profile selected, the server may modify its operations to meet specific
// requirements dictated by the corresponding standards or protocols.
func New(
	profile goidc.Profile,
	issuer string,
	privateJWKS jose.JSONWebKeySet,
	opts ...ProviderOption,
) (
	Provider,
	error,
) {
	// Use the first signature key as the default key.
	var defaultSigKeyID string
	for _, key := range privateJWKS.Keys {
		if key.Use == string(goidc.KeyUsageSignature) {
			defaultSigKeyID = key.KeyID
			break
		}
	}
	if defaultSigKeyID == "" {
		return Provider{}, errors.New("the private jwks doesn't contain any signing key")
	}

	p := Provider{
		config: &oidc.Configuration{
			Profile: profile,
			Host:    issuer,

			ClientManager:       storage.NewClientManager(),
			AuthnSessionManager: storage.NewAuthnSessionManager(),
			GrantSessionManager: storage.NewGrantSessionManager(),

			Scopes:                      []goidc.Scope{goidc.ScopeOpenID},
			TokenOptionsFunc:            defaultTokenOptionsFunc(defaultSigKeyID),
			ShouldIssueRefreshTokenFunc: defaultShouldIssueRefreshTokenFunc(),
			PrivateJWKS:                 privateJWKS,
			UserDefaultSigKeyID:         defaultSigKeyID,
			UserSigKeyIDs:               []string{defaultSigKeyID},
			IDTokenLifetimeSecs:         defaultIDTokenLifetimeSecs,
			GrantTypes:                  []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:               []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			SubIdentifierTypes: []goidc.SubjectIdentifierType{
				goidc.SubjectIdentifierPublic,
			},
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeNormal},

			EndpointWellKnown:           defaultEndpointWellKnown,
			EndpointJWKS:                defaultEndpointJSONWebKeySet,
			EndpointToken:               defaultEndpointToken,
			EndpointAuthorize:           defaultEndpointAuthorize,
			EndpointPushedAuthorization: defaultEndpointPushedAuthorizationRequest,
			EndpointDCR:                 defaultEndpointDynamicClient,
			EndpointUserInfo:            defaultEndpointUserInfo,
			EndpointIntrospection:       defaultEndpointTokenIntrospection,
			EndpointTokenRevocation:     defaultEndpointTokenRevocation,

			AuthnSessionTimeoutSecs:  defaultAuthnSessionTimeoutSecs,
			AssertionLifetimeSecs:    defaultJWTLifetimeSecs,
			RefreshTokenLifetimeSecs: defaultRefreshTokenLifetimeSecs,
			PARLifetimeSecs:          defaultPARLifetimeSecs,
			JARLifetimeSecs:          defaultJWTLifetimeSecs,
			JARLeewayTimeSecs:        defaultJWTLeewayTimeSecs,
			JARMLifetimeSecs:         defaultJWTLifetimeSecs,
			DPoPLifetimeSecs:         defaultJWTLifetimeSecs,
			DPoPLeewayTimeSecs:       defaultJWTLeewayTimeSecs,

			JARMDefaultContentEncAlg: jose.A128CBC_HS256,
			JARMContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
			UserDefaultContentEncAlg: jose.A128CBC_HS256,
			UserContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
			JARDefaultContentEncAlg:  jose.A128CBC_HS256,
			JARContentEncAlgs:        []jose.ContentEncryption{jose.A128CBC_HS256},

			ClientCertFunc: defaultClientCertFunc(),
		},
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return Provider{}, err
		}
	}

	if err := p.validate(); err != nil {
		return Provider{}, err
	}

	return p, nil
}

// Handler returns an HTTP handler with all the logic defined for the openid
// provider.
// This may be used to add the oidc logic to a HTTP server.
//
//	server := http.NewServeMux()
//	server.Handle("/", op.Handler())
func (p Provider) Handler() http.Handler {

	server := http.NewServeMux()

	discovery.RegisterHandlers(server, p.config)
	token.RegisterHandlers(server, p.config)
	authorize.RegisterHandlers(server, p.config)
	userinfo.RegisterHandlers(server, p.config)
	dcr.RegisterHandlers(server, p.config)

	handler := goidc.CacheControlMiddleware(server)
	return handler
}

func (p Provider) Run(
	address string,
	middlewares ...goidc.MiddlewareFunc,
) error {
	handler := p.Handler()
	for _, middleware := range middlewares {
		handler = middleware(handler)
	}
	return http.ListenAndServe(address, handler)
}

// RunTLS runs the provider on TLS mode.
// This is intended for development purposes and must not be used for production
// environments.
func (p Provider) RunTLS(
	tlsOpts TLSOptions,
	middlewares ...goidc.MiddlewareFunc,
) error {

	mux := http.NewServeMux()

	clientAuth := tls.NoClientCert
	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}

	hostURL, err := url.Parse(p.config.Host)
	if err != nil {
		return err
	}
	// Remove the port from the host name if any.
	host := strings.Split(hostURL.Host, ":")[0]
	mux.Handle(host+"/", handler)

	if p.config.MTLSIsEnabled {
		clientAuth = tls.VerifyClientCertIfGiven
		mtlsHostURL, err := url.Parse(p.config.MTLSHost)
		if err != nil {
			return err
		}

		// Remove the port from the host name if any.
		mtlsHost := strings.Split(mtlsHostURL.Host, ":")[0]
		mux.Handle(mtlsHost+"/", handler)
	}

	server := &http.Server{
		Addr:    tlsOpts.TLSAddress,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:    tlsOpts.CaCertPool,
			ClientAuth:   clientAuth,
			CipherSuites: tlsOpts.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(tlsOpts.ServerCert, tlsOpts.ServerKey)
}

// TokenInfo retrieves details about the access token included in the request.
// If the token was issued with mechanisms such as DPoP (Demonstrating Proof
// of Possession) or TLS binding, the function also validates these proofs to
// ensure the token's ownership.
func (p Provider) TokenInfo(
	w http.ResponseWriter,
	r *http.Request,
) (
	goidc.TokenInfo,
	error,
) {
	ctx := oidc.NewContext(w, r, p.config)
	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.TokenInfo{}, errors.New("no token informed")
	}

	tokenInfo, err := token.IntrospectionInfo(ctx, accessToken)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if tokenInfo.Confirmation == nil {
		return tokenInfo, nil
	}

	if err := token.ValidatePoP(
		ctx,
		accessToken,
		*tokenInfo.Confirmation,
	); err != nil {
		return goidc.TokenInfo{}, err
	}

	return tokenInfo, nil
}

// Client is a shortcut to fetch clients using the client storage.
func (p *Provider) Client(
	ctx context.Context,
	id string,
) (
	*goidc.Client,
	error,
) {
	for _, staticClient := range p.config.StaticClients {
		if staticClient.ID == id {
			return staticClient, nil
		}
	}

	return p.config.ClientManager.Client(ctx, id)
}

func (p Provider) validate() error {
	return runValidations(
		p.config,
		validateJWKS,
		validateSigKeys,
		validateEncKeys,
		validatePrivateKeyJWTSigAlgs,
		validateClientSecretJWTSigAlgs,
		validateIntrospectionClientAuthnMethods,
		validateJAREnc,
		validateJARMEnc,
		validateTokenBinding,
	)
}

type TLSOptions struct {
	TLSAddress   string
	ServerCert   string
	ServerKey    string
	CipherSuites []uint16
	CaCertPool   *x509.CertPool
}
