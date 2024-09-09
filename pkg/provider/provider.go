package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"

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

type Provider interface {
	// Handler returns an HTTP handler with all the logic defined for the openid
	// provider.
	//
	// This may be used to add the oidc logic to a HTTP server.
	//	server := http.NewServeMux()
	//	server.Handle("/", op.Handler())
	Handler() http.Handler
	Run(address string, middlewares ...goidc.MiddlewareFunc) error
	RunTLS(opts TLSOptions, middlewares ...goidc.MiddlewareFunc) error
	Client(ctx context.Context, id string) (*goidc.Client, error)
	// TokenInfo returns information about the access token sent in the request.
	// It also validates proof of possesions with DPoP and/or TLS binding if the
	// token was created with these mechanisms.
	TokenInfo(http.ResponseWriter, *http.Request) goidc.TokenInfo
}

// New creates a new openid provider.
// By default, all clients and sessions are stored in memory and JWTs are
// signed with the first signing key in the JWKS.
func New(
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
		return nil, errors.New("the private jwks doesn't contain any signing key")
	}

	p := &provider{
		config: oidc.Configuration{
			Host: issuer,

			ClientManager:       storage.NewClientManager(),
			AuthnSessionManager: storage.NewAuthnSessionManager(),
			GrantSessionManager: storage.NewGrantSessionManager(),

			Scopes:              []goidc.Scope{goidc.ScopeOpenID},
			TokenOptionsFunc:    defaultTokenOptionsFunc(defaultSigKeyID),
			PrivateJWKS:         privateJWKS,
			UserDefaultSigKeyID: defaultSigKeyID,
			UserSigKeyIDs:       []string{defaultSigKeyID},
			IDTokenLifetimeSecs: defaultIDTokenLifetimeSecs,
			GrantTypes:          []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:       []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeQuery,
				goidc.ResponseModeFragment,
				goidc.ResponseModeFormPost,
			},
			SubIdentifierTypes: []goidc.SubjectIdentifierType{
				goidc.SubjectIdentifierPublic,
			},
			ClaimTypes:                  []goidc.ClaimType{goidc.ClaimTypeNormal},
			AuthnSessionTimeoutSecs:     defaultAuthnSessionTimeoutSecs,
			AssertionLifetimeSecs:       defaultJWTLifetimeSecs,
			EndpointWellKnown:           defaultEndpointWellKnown,
			EndpointJWKS:                defaultEndpointJSONWebKeySet,
			EndpointToken:               defaultEndpointToken,
			EndpointAuthorize:           defaultEndpointAuthorize,
			EndpointPushedAuthorization: defaultEndpointPushedAuthorizationRequest,
			EndpointDCR:                 defaultEndpointDynamicClient,
			EndpointUserInfo:            defaultEndpointUserInfo,
			EndpointIntrospection:       defaultEndpointTokenIntrospection,
			ClientCertFunc:              defaultClientCertFunc(),
		},
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	if err := p.validate(); err != nil {
		return nil, err
	}

	return p, nil
}

type provider struct {
	config oidc.Configuration
}

func (p *provider) Handler() http.Handler {

	server := http.NewServeMux()

	discovery.RegisterHandlers(server, &p.config)
	token.RegisterHandlers(server, &p.config)
	authorize.RegisterHandlers(server, &p.config)
	userinfo.RegisterHandlers(server, &p.config)
	dcr.RegisterHandlers(server, &p.config)

	return server
}

func (p *provider) Run(
	address string,
	middlewares ...goidc.MiddlewareFunc,
) error {
	handler := p.Handler()
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}
	handler = newCacheControlMiddleware(handler)
	return http.ListenAndServe(address, handler)
}

func (p *provider) RunTLS(
	config TLSOptions,
	middlewares ...goidc.MiddlewareFunc,
) error {

	mux := http.NewServeMux()

	clientAuth := tls.NoClientCert
	handler := p.Handler()
	handler = newCacheControlMiddleware(handler)
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}

	hostURL, err := url.Parse(p.config.Host)
	if err != nil {
		return err
	}
	mux.Handle(hostURL.Host+"/", handler)

	if p.config.MTLSIsEnabled {
		clientAuth = tls.VerifyClientCertIfGiven
		mtlsHostURL, err := url.Parse(p.config.MTLSHost)
		if err != nil {
			return err
		}
		handler = newClientCertificateMiddleware(handler)
		mux.Handle(mtlsHostURL.Host+"/", handler)
	}

	server := &http.Server{
		Addr:    config.TLSAddress,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:    config.CaCertPool,
			ClientAuth:   clientAuth,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCert, config.ServerKey)
}

func (p *provider) TokenInfo(
	w http.ResponseWriter,
	r *http.Request,
) goidc.TokenInfo {
	ctx := oidc.NewContext(w, r, p.config)
	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.TokenInfo{}
	}

	tokenInfo := token.IntrospectionInfo(ctx, accessToken)
	if tokenInfo.Confirmation == nil {
		return tokenInfo
	}

	if err := token.ValidatePoP(
		ctx,
		accessToken,
		tokenType,
		*tokenInfo.Confirmation,
	); err != nil {
		return goidc.TokenInfo{}
	}

	return tokenInfo
}

// Client is a shortcut to fetch clients using the client storage.
func (p *provider) Client(
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

func (p *provider) validate() error {
	return runValidations(
		*p,
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
