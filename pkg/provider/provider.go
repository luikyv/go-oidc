package provider

import (
	"context"
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
// The profile parameter adjusts the server's behavior for non-configurable
// settings, ensuring compliance with the associated specification. Depending on
// the profile selected, the server may modify its operations to meet specific
// requirements dictated by the corresponding standards or protocols.
//
// Default Settings:
//   - All clients and sessions are stored in memory.
//   - ID tokens and user info responses are signed using RS256.
//     Ensure a JWK supporting RS256 is available in the server's JWKS.
//     This algorithm can be overridden with the [WithUserSignatureAlgs] option.
//   - Access tokens are issued as opaque tokens.
func New(
	profile goidc.Profile,
	issuer string,
	privateJWKSFunc goidc.PrivateJWKSFunc,
	opts ...ProviderOption,
) (
	Provider,
	error,
) {

	p := Provider{
		config: &oidc.Configuration{
			Profile:         profile,
			Host:            issuer,
			PrivateJWKSFunc: privateJWKSFunc,
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

// TokenInfo processes a request to retrieve information about an access token.
// It extracts the access token from the request, performs introspection to validate
// and gather information about the token, and checks for Proof of Possession (PoP)
// if required.
// If the token is valid and PoP validation (if any) is successful, the function
// returns token information; otherwise, it returns an appropriate error.
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
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	info, err := token.IntrospectionInfo(ctx, accessToken)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if info.Confirmation == nil {
		return info, nil
	}

	if err := token.ValidatePoP(ctx, accessToken, *info.Confirmation); err != nil {
		return goidc.TokenInfo{}, err
	}
	return info, nil
}

func (p Provider) Client(
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

func (p Provider) NotifyAuth(
	ctx context.Context,
	authReqID string,
) error {
	oidcCtx := oidc.FromContext(ctx, p.config)
	return token.NotifyCIBAGrant(oidcCtx, authReqID)
}

func (p Provider) setDefaults() error {
	p.config.UserDefaultSigAlg = nonZeroOrDefault(p.config.UserDefaultSigAlg,
		defaultUserInfoSigAlg)

	p.config.UserSigAlgs = nonZeroOrDefault(p.config.UserSigAlgs,
		[]jose.SignatureAlgorithm{defaultUserInfoSigAlg})

	p.config.Scopes = nonZeroOrDefault(p.config.Scopes,
		[]goidc.Scope{goidc.ScopeOpenID})

	p.config.ClientManager = nonZeroOrDefault(p.config.ClientManager,
		goidc.ClientManager(storage.NewClientManager()))

	p.config.AuthnSessionManager = nonZeroOrDefault(p.config.AuthnSessionManager,
		goidc.AuthnSessionManager(storage.NewAuthnSessionManager()))

	p.config.GrantSessionManager = nonZeroOrDefault(p.config.GrantSessionManager,
		goidc.GrantSessionManager(storage.NewGrantSessionManager()))

	p.config.TokenOptionsFunc = nonZeroOrDefault(p.config.TokenOptionsFunc,
		defaultTokenOptionsFunc())

	p.config.ResponseModes = []goidc.ResponseMode{goidc.ResponseModeQuery,
		goidc.ResponseModeFragment, goidc.ResponseModeFormPost}

	p.config.DefaultSubIdentifierType = nonZeroOrDefault(p.config.DefaultSubIdentifierType,
		goidc.SubIdentifierPublic)

	p.config.SubIdentifierTypes = nonZeroOrDefault(p.config.SubIdentifierTypes,
		[]goidc.SubIdentifierType{goidc.SubIdentifierPublic})

	p.config.ClaimTypes = nonZeroOrDefault(p.config.ClaimTypes,
		[]goidc.ClaimType{goidc.ClaimTypeNormal})

	p.config.AuthnSessionTimeoutSecs = nonZeroOrDefault(p.config.AuthnSessionTimeoutSecs,
		defaultAuthnSessionTimeoutSecs)

	p.config.IDTokenLifetimeSecs = nonZeroOrDefault(p.config.IDTokenLifetimeSecs,
		defaultIDTokenLifetimeSecs)

	p.config.EndpointWellKnown = nonZeroOrDefault(p.config.EndpointWellKnown,
		defaultEndpointWellKnown)

	p.config.EndpointJWKS = nonZeroOrDefault(p.config.EndpointJWKS,
		defaultEndpointJSONWebKeySet)

	p.config.EndpointToken = nonZeroOrDefault(p.config.EndpointToken,
		defaultEndpointToken)

	p.config.EndpointAuthorize = nonZeroOrDefault(p.config.EndpointAuthorize,
		defaultEndpointAuthorize)

	p.config.EndpointUserInfo = nonZeroOrDefault(p.config.EndpointUserInfo,
		defaultEndpointUserInfo)

	if slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) {
		p.config.ResponseTypes = append(p.config.ResponseTypes, goidc.ResponseTypeCode)
	}

	if slices.Contains(p.config.GrantTypes, goidc.GrantImplicit) {
		p.config.ResponseTypes = append(p.config.ResponseTypes, goidc.ResponseTypeToken,
			goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken)
	}

	if slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) &&
		slices.Contains(p.config.GrantTypes, goidc.GrantImplicit) {
		p.config.ResponseTypes = append(p.config.ResponseTypes, goidc.ResponseTypeCodeAndIDToken,
			goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken)
	}

	authnMethods := append(p.config.TokenAuthnMethods,
		p.config.TokenIntrospectionAuthnMethods...)
	authnMethods = append(authnMethods,
		p.config.TokenRevocationAuthnMethods...)
	if slices.Contains(authnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		p.config.PrivateKeyJWTSigAlgs = nonZeroOrDefault(p.config.PrivateKeyJWTSigAlgs,
			[]jose.SignatureAlgorithm{defaultPrivateKeyJWTSigAlg})
	}
	if slices.Contains(authnMethods, goidc.ClientAuthnSecretJWT) {
		p.config.ClientSecretJWTSigAlgs = nonZeroOrDefault(p.config.ClientSecretJWTSigAlgs,
			[]jose.SignatureAlgorithm{defaultSecretJWTSigAlg})
	}
	if slices.Contains(authnMethods, goidc.ClientAuthnPrivateKeyJWT) ||
		slices.Contains(authnMethods, goidc.ClientAuthnSecretJWT) {
		p.config.AssertionLifetimeSecs = nonZeroOrDefault(p.config.AssertionLifetimeSecs,
			defaultJWTLifetimeSecs)
	}

	if p.config.DCRIsEnabled {
		p.config.EndpointDCR = nonZeroOrDefault(p.config.EndpointDCR,
			defaultEndpointDynamicClient)
	}

	if p.config.PARIsEnabled {
		p.config.EndpointPushedAuthorization = nonZeroOrDefault(p.config.EndpointPushedAuthorization,
			defaultEndpointPushedAuthorizationRequest)
	}

	if p.config.JARIsEnabled {
		p.config.JARLifetimeSecs = nonZeroOrDefault(p.config.JARLifetimeSecs,
			defaultJWTLifetimeSecs)
		p.config.JARLeewayTimeSecs = nonZeroOrDefault(p.config.JARLeewayTimeSecs,
			defaultJWTLeewayTimeSecs)
	}

	if p.config.JAREncIsEnabled {
		p.config.JARContentEncAlgs = nonZeroOrDefault(p.config.JARContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256})
	}

	if p.config.JARMIsEnabled {
		p.config.JARMLifetimeSecs = nonZeroOrDefault(p.config.JARMLifetimeSecs,
			defaultJWTLifetimeSecs)
		p.config.ResponseModes = append(p.config.ResponseModes, goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT, goidc.ResponseModeFragmentJWT, goidc.ResponseModeFormPostJWT)
	}

	if p.config.JARMEncIsEnabled {
		p.config.JARMDefaultContentEncAlg = nonZeroOrDefault(p.config.JARMDefaultContentEncAlg,
			jose.A128CBC_HS256)
		p.config.JARMContentEncAlgs = nonZeroOrDefault(p.config.JARMContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256})
	}

	if p.config.DPoPIsEnabled {
		p.config.DPoPLifetimeSecs = nonZeroOrDefault(p.config.DPoPLifetimeSecs,
			defaultJWTLifetimeSecs)
		p.config.DPoPLeewayTimeSecs = nonZeroOrDefault(p.config.DPoPLeewayTimeSecs,
			defaultJWTLeewayTimeSecs)
	}

	if p.config.TokenIntrospectionIsEnabled {
		p.config.EndpointIntrospection = nonZeroOrDefault(p.config.EndpointIntrospection,
			defaultEndpointTokenIntrospection)
	}

	if p.config.TokenRevocationIsEnabled {
		p.config.EndpointTokenRevocation = nonZeroOrDefault(p.config.EndpointTokenRevocation,
			defaultEndpointTokenRevocation)
	}

	if p.config.UserEncIsEnabled {
		p.config.UserDefaultContentEncAlg = nonZeroOrDefault(p.config.UserDefaultContentEncAlg,
			jose.A128CBC_HS256)
		p.config.UserContentEncAlgs = nonZeroOrDefault(p.config.UserContentEncAlgs,
			[]jose.ContentEncryption{jose.A128CBC_HS256})
	}

	if slices.Contains(p.config.SubIdentifierTypes, goidc.SubIdentifierPairwise) {
		p.config.GeneratePairwiseSubIDFunc = nonZeroOrDefault(p.config.GeneratePairwiseSubIDFunc,
			defaultGeneratePairwiseSubIDFunc())
	}

	if p.config.CIBAIsEnabled {
		p.config.EndpointCIBA = nonZeroOrDefault(p.config.EndpointCIBA,
			defaultEndpointCIBA)
	}

	return nil
}

func (p Provider) validate() error {
	return runValidations(
		p.config,
		validateJAREnc,
		validateJARMEnc,
		validateTokenBinding,
	)
}

// nonZeroOrDefault returns the first argument `s1“ if it is non-nil and non-zero.
// Otherwise, it returns the second argument `s2` as the default value.
//
// Example:
//
//	nonZeroOrDefault(42, 100) // returns 42
//	nonZeroOrDefault(0, 100)  // returns 100
//	nonZeroOrDefault("", "default") // returns "default"
func nonZeroOrDefault[T any](s1 T, s2 T) T {
	if isNil(s1) || reflect.ValueOf(s1).IsZero() {
		return s2
	}

	return s1
}

func isNil(i any) bool {
	return i == nil
}
