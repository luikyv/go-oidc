package provider

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"

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

	p := Provider{
		config: &oidc.Configuration{
			Profile:     profile,
			Host:        issuer,
			PrivateJWKS: privateJWKS,
		},
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return Provider{}, err
		}
	}

	if err := p.setDefaults(); err != nil {
		return Provider{}, err
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

func (p Provider) setDefaults() error {
	// Use the first signature key as the default key.
	defaultSigKeyID, ok := firstSigKeyID(p.config.PrivateJWKS)
	if !ok {
		return errors.New("the private jwks doesn't contain any signing key")
	}

	p.config.UserDefaultSigKeyID = nonEmptyOrDefault(
		p.config.UserDefaultSigKeyID,
		defaultSigKeyID,
	)
	p.config.UserSigKeyIDs = nonNilOrDefault(
		p.config.UserSigKeyIDs,
		[]string{defaultSigKeyID},
	)
	p.config.Scopes = nonNilOrDefault(
		p.config.Scopes,
		[]goidc.Scope{goidc.ScopeOpenID},
	)
	p.config.ClientManager = nonNilOrDefault(
		p.config.ClientManager,
		goidc.ClientManager(storage.NewClientManager()),
	)
	p.config.AuthnSessionManager = nonNilOrDefault(
		p.config.AuthnSessionManager,
		goidc.AuthnSessionManager(storage.NewAuthnSessionManager()),
	)
	p.config.GrantSessionManager = nonNilOrDefault(
		p.config.GrantSessionManager,
		goidc.GrantSessionManager(storage.NewGrantSessionManager()),
	)
	p.config.TokenOptionsFunc = nonNilOrDefault(
		p.config.TokenOptionsFunc,
		defaultTokenOptionsFunc(defaultSigKeyID),
	)
	p.config.ResponseModes = []goidc.ResponseMode{
		goidc.ResponseModeQuery,
		goidc.ResponseModeFragment,
		goidc.ResponseModeFormPost,
	}
	p.config.SubIdentifierTypes = nonNilOrDefault(
		p.config.SubIdentifierTypes,
		[]goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
	)
	p.config.ClaimTypes = nonNilOrDefault(
		p.config.ClaimTypes,
		[]goidc.ClaimType{goidc.ClaimTypeNormal},
	)
	p.config.AuthnSessionTimeoutSecs = nonZeroOrDefault(
		p.config.AuthnSessionTimeoutSecs,
		defaultAuthnSessionTimeoutSecs,
	)
	p.config.IDTokenLifetimeSecs = nonZeroOrDefault(
		p.config.IDTokenLifetimeSecs,
		defaultIDTokenLifetimeSecs,
	)
	p.config.EndpointWellKnown = nonEmptyOrDefault(
		p.config.EndpointWellKnown,
		defaultEndpointWellKnown,
	)
	p.config.EndpointJWKS = nonEmptyOrDefault(
		p.config.EndpointJWKS,
		defaultEndpointJSONWebKeySet,
	)
	p.config.EndpointToken = nonEmptyOrDefault(
		p.config.EndpointToken,
		defaultEndpointToken,
	)
	p.config.EndpointAuthorize = nonEmptyOrDefault(
		p.config.EndpointAuthorize,
		defaultEndpointAuthorize,
	)
	p.config.EndpointUserInfo = nonEmptyOrDefault(
		p.config.EndpointUserInfo,
		defaultEndpointUserInfo,
	)

	if slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) {
		p.config.ResponseTypes = append(
			p.config.ResponseTypes,
			goidc.ResponseTypeCode,
		)
	}

	if slices.Contains(p.config.GrantTypes, goidc.GrantImplicit) {
		p.config.ResponseTypes = append(
			p.config.ResponseTypes,
			goidc.ResponseTypeToken,
			goidc.ResponseTypeIDToken,
			goidc.ResponseTypeIDTokenAndToken,
		)
	}

	if slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) &&
		slices.Contains(p.config.GrantTypes, goidc.GrantImplicit) {
		p.config.ResponseTypes = append(
			p.config.ResponseTypes,
			goidc.ResponseTypeCodeAndIDToken,
			goidc.ResponseTypeCodeAndToken,
			goidc.ResponseTypeCodeAndIDTokenAndToken,
		)
	}

	if slices.Contains(p.config.GrantTypes, goidc.GrantRefreshToken) {
		p.config.RefreshTokenLifetimeSecs = nonZeroOrDefault(
			p.config.RefreshTokenLifetimeSecs,
			defaultRefreshTokenLifetimeSecs,
		)
	}

	authnMethods := append(
		p.config.TokenAuthnMethods,
		p.config.TokenIntrospectionAuthnMethods...,
	)
	authnMethods = append(
		authnMethods,
		p.config.TokenRevocationAuthnMethods...,
	)
	if slices.Contains(authnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		p.config.PrivateKeyJWTSigAlgs = nonNilOrDefault(
			p.config.PrivateKeyJWTSigAlgs,
			[]jose.SignatureAlgorithm{defaultPrivateKeyJWTSigAlg},
		)
	}
	if slices.Contains(authnMethods, goidc.ClientAuthnSecretJWT) {
		p.config.ClientSecretJWTSigAlgs = nonNilOrDefault(
			p.config.ClientSecretJWTSigAlgs,
			[]jose.SignatureAlgorithm{defaultSecretJWTSigAlg},
		)
	}
	if slices.Contains(authnMethods, goidc.ClientAuthnPrivateKeyJWT) ||
		slices.Contains(authnMethods, goidc.ClientAuthnSecretJWT) {
		p.config.AssertionLifetimeSecs = nonZeroOrDefault(
			p.config.AssertionLifetimeSecs,
			defaultJWTLifetimeSecs,
		)
	}

	if p.config.DCRIsEnabled {
		p.config.EndpointDCR = nonEmptyOrDefault(
			p.config.EndpointDCR,
			defaultEndpointDynamicClient,
		)
	}

	if p.config.PARIsEnabled {
		p.config.EndpointPushedAuthorization = nonEmptyOrDefault(
			p.config.EndpointPushedAuthorization,
			defaultEndpointPushedAuthorizationRequest,
		)
		p.config.PARLifetimeSecs = nonZeroOrDefault(
			p.config.PARLifetimeSecs,
			defaultPARLifetimeSecs,
		)
	}

	if p.config.JARIsEnabled {
		p.config.JARLifetimeSecs = nonZeroOrDefault(
			p.config.JARLifetimeSecs,
			defaultJWTLifetimeSecs,
		)
		p.config.JARLeewayTimeSecs = nonZeroOrDefault(
			p.config.JARLeewayTimeSecs,
			defaultJWTLeewayTimeSecs,
		)
	}

	if p.config.JAREncIsEnabled {
		p.config.JARContentEncAlgs = nonNilOrDefault(
			p.config.JARContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256},
		)
	}

	if p.config.JARMIsEnabled {
		p.config.JARMLifetimeSecs = nonZeroOrDefault(
			p.config.JARMLifetimeSecs,
			defaultJWTLifetimeSecs,
		)
		p.config.ResponseModes = append(
			p.config.ResponseModes,
			goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT,
			goidc.ResponseModeFragmentJWT,
			goidc.ResponseModeFormPostJWT,
		)
	}

	if p.config.JARMEncIsEnabled {
		p.config.JARMDefaultContentEncAlg = nonEmptyOrDefault(
			p.config.JARMDefaultContentEncAlg,
			jose.A128CBC_HS256,
		)
		p.config.JARMContentEncAlgs = nonNilOrDefault(
			p.config.JARMContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256},
		)
	}

	if p.config.DPoPIsEnabled {
		p.config.DPoPLifetimeSecs = nonZeroOrDefault(
			p.config.DPoPLifetimeSecs,
			defaultJWTLifetimeSecs,
		)
		p.config.DPoPLeewayTimeSecs = nonZeroOrDefault(
			p.config.DPoPLeewayTimeSecs,
			defaultJWTLeewayTimeSecs,
		)
	}

	if p.config.TokenIntrospectionIsEnabled {
		p.config.EndpointIntrospection = nonEmptyOrDefault(
			p.config.EndpointIntrospection,
			defaultEndpointTokenIntrospection,
		)
		// Set the defaults token introspection authn methods to the same as for the
		// token endpoint.
		p.config.TokenIntrospectionAuthnMethods = nonNilOrDefault(
			p.config.TokenIntrospectionAuthnMethods,
			p.config.TokenAuthnMethods,
		)
	}

	if p.config.TokenRevocationIsEnabled {
		p.config.EndpointTokenRevocation = nonEmptyOrDefault(
			p.config.EndpointTokenRevocation,
			defaultEndpointTokenRevocation,
		)
		// Set the defaults token revocation authn methods to the same as for the
		// token endpoint.
		p.config.TokenRevocationAuthnMethods = nonNilOrDefault(
			p.config.TokenRevocationAuthnMethods,
			p.config.TokenAuthnMethods,
		)
	}

	if p.config.UserEncIsEnabled {
		p.config.UserDefaultContentEncAlg = nonEmptyOrDefault(
			p.config.UserDefaultContentEncAlg,
			jose.A128CBC_HS256,
		)
		p.config.UserContentEncAlgs = nonNilOrDefault(
			p.config.UserContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256},
		)
	}

	return nil
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

func nonEmptyOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).String() == "" {
		return s2
	}

	return s1
}

func nonZeroOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).Int() == 0 {
		return s2
	}

	return s1
}

func nonNilOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).IsNil() {
		return s2
	}

	return s1
}

func firstSigKeyID(jwks jose.JSONWebKeySet) (string, bool) {
	for _, key := range jwks.Keys {
		if key.KeyID != "" && key.Use == string(goidc.KeyUsageSignature) {
			return key.KeyID, true
		}
	}
	return "", false

}
