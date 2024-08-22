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
	"github.com/luikyv/go-oidc/internal/client"
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

	p := &provider{
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
	p.config.Storage.Client = storage.NewClientManager()
	p.config.Storage.AuthnSession = storage.NewAuthnSessionManager()
	p.config.Storage.GrantSession = storage.NewGrantSessionManager()

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
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	if err := p.validateConfiguration(); err != nil {
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
	client.RegisterHandlers(server, &p.config)

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

	handler := p.Handler()
	handler = newCacheControlMiddleware(handler)
	for _, wrapHandler := range middlewares {
		handler = wrapHandler(handler)
	}

	mux := http.NewServeMux()

	hostURL, err := url.Parse(p.config.Host)
	if err != nil {
		return err
	}
	mux.Handle(hostURL.Host+"/", handler)

	if p.config.MTLS.IsEnabled {
		mtlsHostURL, err := url.Parse(p.config.MTLS.Host)
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
			ClientCAs:    config.CaCertificatePool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

// TokenInfo returns information about the access token sent in the request.
// It also validates token binding (DPoP or TLS).
func (p *provider) TokenInfo(
	req *http.Request,
	resp http.ResponseWriter,
) goidc.TokenInfo {
	ctx := oidc.NewContext(p.config, req, resp)
	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.TokenInfo{}
	}

	tokenInfo := token.IntrospectionInfo(ctx, accessToken)
	if tokenInfo.Confirmation == nil {
		return tokenInfo
	}

	if err := token.ValidatePoP(ctx, accessToken, tokenType, *tokenInfo.Confirmation); err != nil {
		return goidc.TokenInfo{}
	}

	return tokenInfo
}

// Client is a shortcut to fetch clients using the client storage.
func (p *provider) Client(
	ctx context.Context,
	clientID string,
) (
	*goidc.Client,
	error,
) {
	return p.config.Storage.Client.Get(ctx, clientID)
}

// TODO: Refactor.
func (p *provider) validateConfiguration() error {
	return runValidations(
		*p,
		validateJWKS,
		validateSignatureKeys,
		validateEncryptionKeys,
		validatePrivateKeyJWTSignatureAlgorithms,
		validateClientSecretJWTSignatureAlgorithms,
		validateIntrospectionClientAuthnMethods,
		validateJAREncryption,
		validateJARMEncryption,
		validateTokenBinding,
		validateOpenIDProfile,
		validateFAPI2Profile,
	)
}

type TLSOptions struct {
	TLSAddress        string
	ServerCertificate string
	ServerKey         string
	CipherSuites      []uint16
	CaCertificatePool *x509.CertPool
}
