package provider

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/federation"
	"github.com/luikyv/go-oidc/internal/logout"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/ssf"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Provider struct {
	config oidc.Configuration
}

// New creates a new openid provider.
//
// The parameter "profile" adjusts the server's behavior for non-configurable
// settings, ensuring compliance with the associated specification. Depending on
// the profile selected, the server may modify its operations to meet specific
// requirements dictated by the corresponding standards or protocols.
//
// The "jwksFunc" parameter provides the server's JSON Web Key Set (JWKS),
// used for signing, decryption, and exposure via the JWKS endpoint.
// Typically, it should return both private and public key material.
// If private keys are unavailable or granular control over signing is required,
// "jwksFunc" can be configured to return only public key material. In such cases,
// the [WithSignerFunc] option must be provided to handle signing operations.
// Similarly, if server-side encryption (e.g., JAR encryption) is enabled,
// the [WithDecrypterFunc] option must also be configured for decryption support.
// For operations like signature verification, only the public key material is
// needed, which can be retrieved using "jwksFunc".
//
// Default Settings:
//   - All clients and sessions are stored in memory.
//   - ID tokens are signed using RS256. Ensure a JWK supporting RS256 is
//     available in the server's JWKS.
//     This algorithm can be overridden with [WithIDTokenSignatureAlgs].
//   - Access tokens are issued as opaque tokens.
func New(profile goidc.Profile, issuer string, jwksFunc goidc.JWKSFunc, opts ...Option) (*Provider, error) {

	op := &Provider{
		config: oidc.Configuration{
			Profile:  profile,
			Host:     issuer,
			JWKSFunc: jwksFunc,
		},
	}

	if err := op.WithOptions(opts...); err != nil {
		return nil, err
	}

	return op, nil
}

func (op *Provider) WithOptions(opts ...Option) error {
	for _, opt := range opts {
		if err := opt(op); err != nil {
			return err
		}
	}

	if err := op.setDefaults(); err != nil {
		return err
	}

	return op.validate()
}

func (op *Provider) Issuer() string {
	return op.config.Host
}

// Handler returns an HTTP handler with all the logic defined for the openid provider.
// This may be used to add the oidc logic to a HTTP server.
//
//	mux := http.NewServeMux()
//	mux.Handle("/", op.Handler())
func (op *Provider) Handler(middlewares ...goidc.MiddlewareFunc) http.Handler {
	mux := http.NewServeMux()
	op.RegisterRoutes(mux, middlewares...)
	return mux
}

func (op Provider) RegisterRoutes(mux *http.ServeMux, middlewares ...goidc.MiddlewareFunc) {
	middlewares = append(middlewares, goidc.CacheControlMiddleware)
	discovery.RegisterHandlers(mux, &op.config, middlewares...)
	token.RegisterHandlers(mux, &op.config, middlewares...)
	authorize.RegisterHandlers(mux, &op.config, middlewares...)
	userinfo.RegisterHandlers(mux, &op.config, middlewares...)
	dcr.RegisterHandlers(mux, &op.config, middlewares...)
	federation.RegisterHandlers(mux, &op.config, middlewares...)
	logout.RegisterHandlers(mux, &op.config, middlewares...)
	ssf.RegisterHandlers(mux, &op.config, middlewares...)
}

func (op *Provider) Run(address string, middlewares ...goidc.MiddlewareFunc) error {
	server := &http.Server{
		Addr:        address,
		Handler:     op.Handler(middlewares...),
		ReadTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func (op *Provider) TokenInfo(ctx context.Context, tkn string) (goidc.TokenInfo, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.IntrospectionInfo(oidcCtx, tkn)
}

// TokenInfoFromRequest processes a request to retrieve information about an access token.
// It extracts the access token from the request, performs introspection to validate
// and gather information about the token, and checks for Proof of Possession (PoP) if required.
// If the token is valid and PoP validation (if any) is successful, the function
// returns token information; otherwise, it returns an appropriate error.
func (op *Provider) TokenInfoFromRequest(r *http.Request) (string, goidc.TokenInfo, error) {
	ctx := oidc.NewHTTPContext(nil, r, &op.config)

	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return "", goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	info, err := token.IntrospectionInfo(ctx, accessToken)
	if err != nil {
		return "", goidc.TokenInfo{}, err
	}

	if info.Confirmation == nil {
		return accessToken, info, nil
	}

	if err := token.ValidatePoP(ctx, accessToken, *info.Confirmation); err != nil {
		return "", goidc.TokenInfo{}, err
	}
	return accessToken, info, nil
}

func (op *Provider) SaveClient(ctx context.Context, client *goidc.Client) error {
	return op.config.ClientManager.Save(ctx, client)
}

// Client retrieves a client based on its ID.
// It first checks if the client is a static client configured within the provider.
// If no matching static client is found, fallback to the ClientManager.
func (op *Provider) Client(ctx context.Context, id string) (*goidc.Client, error) {
	for _, staticClient := range op.config.StaticClients {
		if staticClient.ID == id {
			return staticClient, nil
		}
	}

	// TODO: Federation missing.
	return op.config.ClientManager.Client(ctx, id)
}

func (op *Provider) DeleteClient(ctx context.Context, id string) error {
	return op.config.ClientManager.Delete(ctx, id)
}

func (op *Provider) SaveAuthnSession(ctx context.Context, as *goidc.AuthnSession) error {
	return op.config.AuthnSessionManager.Save(ctx, as)
}

func (op *Provider) AuthnSessionByCallbackID(ctx context.Context, callbackID string) (*goidc.AuthnSession, error) {
	return op.config.AuthnSessionManager.SessionByCallbackID(ctx, callbackID)
}

func (op *Provider) AuthnSessionByAuthCode(ctx context.Context, authCode string) (*goidc.AuthnSession, error) {
	return op.config.AuthnSessionManager.SessionByAuthCode(ctx, authCode)
}

func (op *Provider) AuthnSessionByPushedAuthReqID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return op.config.AuthnSessionManager.SessionByPushedAuthReqID(ctx, id)
}

func (op *Provider) AuthnSessionByCIBAAuthID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	return op.config.AuthnSessionManager.SessionByCIBAAuthID(ctx, id)
}

func (op *Provider) DeleteAuthnSession(ctx context.Context, id string) error {
	return op.config.AuthnSessionManager.Delete(ctx, id)
}

func (op *Provider) SaveGrantSession(ctx context.Context, gs *goidc.GrantSession) error {
	return op.config.GrantSessionManager.Save(ctx, gs)
}

func (op *Provider) GrantSessionByTokenID(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return op.config.GrantSessionManager.SessionByTokenID(ctx, id)
}

func (op *Provider) GrantSessionByRefreshToken(ctx context.Context, id string) (*goidc.GrantSession, error) {
	return op.config.GrantSessionManager.SessionByRefreshToken(ctx, id)
}

func (op *Provider) DeleteGrantSession(ctx context.Context, id string) error {
	return op.config.GrantSessionManager.Delete(ctx, id)
}

func (op *Provider) DeleteGrantSessionByAuthCode(ctx context.Context, id string) error {
	return op.config.GrantSessionManager.DeleteByAuthCode(ctx, id)
}

func (op *Provider) SaveLogoutSession(ctx context.Context, session *goidc.LogoutSession) error {
	return op.config.LogoutSessionManager.Save(ctx, session)
}

func (op *Provider) LogoutSessionByCallbackID(ctx context.Context, callbackID string) (*goidc.LogoutSession, error) {
	return op.config.LogoutSessionManager.SessionByCallbackID(ctx, callbackID)
}

func (op *Provider) DeleteLogoutSession(ctx context.Context, id string) error {
	return op.config.LogoutSessionManager.Delete(ctx, id)
}

// NotifyCIBASuccess notifies a client that the user has granted access.
// The behavior varies based on the client's token delivery mode for which the
// auth request ID was issued:
//   - "poll": No notification is sent, and no additional processing occurs.
//     There is no need to call this function for this mode.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token response is sent directly to the client's notification endpoint.
func (op *Provider) NotifyCIBASuccess(ctx context.Context, authReqID string) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.NotifyCIBAGrant(oidcCtx, authReqID)
}

// NotifyCIBAGrantFailure notifies a client that the user has denied access.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token failure response is sent directly to the client's
//     notification endpoint.
func (op *Provider) NotifyCIBAFailure(ctx context.Context, authReqID string, err goidc.Error) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.NotifyCIBAGrantFailure(oidcCtx, authReqID, err)
}

// MakeToken generates a new access token based on the provided grant information
// and stores the corresponding grant session.
//
// This function is intended for scenarios where a token is required for the provider itself.
func (op *Provider) MakeToken(ctx context.Context, gi goidc.GrantInfo) (string, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	client := &goidc.Client{ID: gi.ClientID}

	tkn, err := token.Make(oidcCtx, gi, client)
	if err != nil {
		return "", fmt.Errorf("could not generate a token: %w", err)
	}

	grantSession := token.NewGrantSession(oidcCtx, gi, tkn)
	if err := oidcCtx.SaveGrantSession(grantSession); err != nil {
		return "", fmt.Errorf("could not store the grant session: %w", err)
	}

	return tkn.Value, nil
}

func (op *Provider) RevokeToken(ctx context.Context, tkn string) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	info, err := token.IntrospectionInfo(oidcCtx, tkn)
	if err != nil {
		return err
	}
	_ = oidcCtx.DeleteGrantSession(info.GrantID)
	return nil
}

func (p *Provider) PublishSSFEvent(ctx context.Context, streamID string, event goidc.SSFEvent) error {
	oidcCtx := oidc.NewContext(ctx, &p.config)
	return ssf.PublishEvent(oidcCtx, streamID, event)
}

func (op *Provider) PublishSSFVerificationEvent(ctx context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return ssf.PublishEvent(oidcCtx, streamID, goidc.NewSSFVerificationEvent(streamID, opts))
}

func (op *Provider) setDefaults() error {
	op.config.IDTokenDefaultSigAlg = nonZeroOrDefault(op.config.IDTokenDefaultSigAlg, defaultIDTokenSigAlg)

	op.config.IDTokenSigAlgs = nonZeroOrDefault(op.config.IDTokenSigAlgs, []goidc.SignatureAlgorithm{defaultIDTokenSigAlg})

	op.config.Scopes = nonZeroOrDefault(op.config.Scopes, []goidc.Scope{goidc.ScopeOpenID})

	op.config.ClientManager = nonZeroOrDefault(op.config.ClientManager, goidc.ClientManager(storage.NewClientManager(defaultStorageMaxSize)))

	op.config.AuthnSessionManager = nonZeroOrDefault(op.config.AuthnSessionManager, goidc.AuthnSessionManager(storage.NewAuthnSessionManager(defaultStorageMaxSize)))

	op.config.GrantSessionManager = nonZeroOrDefault(op.config.GrantSessionManager, goidc.GrantSessionManager(storage.NewGrantSessionManager(defaultStorageMaxSize)))

	op.config.TokenOptionsFunc = nonZeroOrDefault(op.config.TokenOptionsFunc, defaultTokenOptionsFunc())

	op.config.ResponseModes = []goidc.ResponseMode{goidc.ResponseModeQuery, goidc.ResponseModeFragment, goidc.ResponseModeFormPost}

	op.config.DefaultSubIdentifierType = nonZeroOrDefault(op.config.DefaultSubIdentifierType, goidc.SubIdentifierPublic)

	op.config.SubIdentifierTypes = nonZeroOrDefault(op.config.SubIdentifierTypes, []goidc.SubIdentifierType{goidc.SubIdentifierPublic})

	op.config.ClaimTypes = nonZeroOrDefault(op.config.ClaimTypes, []goidc.ClaimType{goidc.ClaimTypeNormal})

	op.config.AuthnSessionTimeoutSecs = nonZeroOrDefault(op.config.AuthnSessionTimeoutSecs, defaultAuthnSessionTimeoutSecs)

	op.config.IDTokenLifetimeSecs = nonZeroOrDefault(op.config.IDTokenLifetimeSecs, defaultIDTokenLifetimeSecs)

	op.config.WellKnownEndpoint = nonZeroOrDefault(op.config.WellKnownEndpoint, defaultEndpointWellKnown)

	op.config.JWKSEndpoint = nonZeroOrDefault(op.config.JWKSEndpoint, defaultEndpointJSONWebKeySet)

	op.config.TokenEndpoint = nonZeroOrDefault(op.config.TokenEndpoint, defaultEndpointToken)

	op.config.AuthorizationEndpoint = nonZeroOrDefault(op.config.AuthorizationEndpoint, defaultEndpointAuthorize)

	op.config.UserInfoEndpoint = nonZeroOrDefault(op.config.UserInfoEndpoint, defaultEndpointUserInfo)

	op.config.JWTLifetimeSecs = nonZeroOrDefault(op.config.JWTLifetimeSecs, defaultJWTLifetimeSecs)

	if slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) {
		op.config.ResponseTypes = append(op.config.ResponseTypes, goidc.ResponseTypeCode)
	}

	if slices.Contains(op.config.GrantTypes, goidc.GrantImplicit) {
		op.config.ResponseTypes = append(op.config.ResponseTypes, goidc.ResponseTypeToken,
			goidc.ResponseTypeIDToken, goidc.ResponseTypeIDTokenAndToken)
	}

	if slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) && slices.Contains(op.config.GrantTypes, goidc.GrantImplicit) {
		op.config.ResponseTypes = append(op.config.ResponseTypes, goidc.ResponseTypeCodeAndIDToken,
			goidc.ResponseTypeCodeAndToken, goidc.ResponseTypeCodeAndIDTokenAndToken)
	}

	authnMethods := op.config.TokenAuthnMethods
	authnMethods = append(authnMethods, op.config.TokenIntrospectionAuthnMethods...)
	authnMethods = append(authnMethods, op.config.TokenRevocationAuthnMethods...)
	if slices.Contains(authnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		op.config.PrivateKeyJWTSigAlgs = nonZeroOrDefault(op.config.PrivateKeyJWTSigAlgs, []goidc.SignatureAlgorithm{defaultPrivateKeyJWTSigAlg})
	}
	if slices.Contains(authnMethods, goidc.ClientAuthnSecretJWT) {
		op.config.ClientSecretJWTSigAlgs = nonZeroOrDefault(op.config.ClientSecretJWTSigAlgs, []goidc.SignatureAlgorithm{defaultSecretJWTSigAlg})
	}

	if op.config.DCRIsEnabled {
		op.config.DCREndpoint = nonZeroOrDefault(op.config.DCREndpoint, defaultEndpointDynamicClient)
	}

	if op.config.PARIsEnabled {
		op.config.PAREndpoint = nonZeroOrDefault(op.config.PAREndpoint, defaultEndpointPushedAuthorizationRequest)
	}

	if op.config.JAREncIsEnabled {
		op.config.JARContentEncAlgs = nonZeroOrDefault(op.config.JARContentEncAlgs, []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})
	}

	if op.config.JARMIsEnabled {
		op.config.JARMLifetimeSecs = nonZeroOrDefault(op.config.JARMLifetimeSecs, defaultJWTLifetimeSecs)
		op.config.ResponseModes = append(op.config.ResponseModes, goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT, goidc.ResponseModeFragmentJWT, goidc.ResponseModeFormPostJWT)
	}

	if op.config.JARMEncIsEnabled {
		op.config.JARMDefaultContentEncAlg = nonZeroOrDefault(op.config.JARMDefaultContentEncAlg, goidc.A128CBC_HS256)
		op.config.JARMContentEncAlgs = nonZeroOrDefault(op.config.JARMContentEncAlgs,
			[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})
	}

	if op.config.TokenIntrospectionIsEnabled {
		op.config.IntrospectionEndpoint = nonZeroOrDefault(op.config.IntrospectionEndpoint, defaultEndpointTokenIntrospection)
	}

	if op.config.TokenRevocationIsEnabled {
		op.config.TokenRevocationEndpoint = nonZeroOrDefault(op.config.TokenRevocationEndpoint, defaultEndpointTokenRevocation)
	}

	if op.config.IDTokenEncIsEnabled {
		op.config.IDTokenDefaultContentEncAlg = nonZeroOrDefault(op.config.IDTokenDefaultContentEncAlg, goidc.A128CBC_HS256)
		op.config.IDTokenContentEncAlgs = nonZeroOrDefault(op.config.IDTokenContentEncAlgs, []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})
	}

	if op.config.UserInfoEncIsEnabled {
		op.config.UserInfoDefaultContentEncAlg = nonZeroOrDefault(op.config.UserInfoDefaultContentEncAlg, goidc.A128CBC_HS256)
		op.config.UserInfoContentEncAlgs = nonZeroOrDefault(op.config.UserInfoContentEncAlgs, []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})
	}

	if op.config.CIBAIsEnabled {
		op.config.CIBAEndpoint = nonZeroOrDefault(op.config.CIBAEndpoint, defaultEndpointCIBA)
	}

	if op.config.OpenIDFedIsEnabled {
		op.config.OpenIDFedEndpoint = nonZeroOrDefault(op.config.OpenIDFedEndpoint, defaultEndpointOpenIDFederation)
		op.config.OpenIDFedRegisterClientFunc = federation.RegisterClient
		op.config.OpenIDFedEntityStatementSigAlgs = nonZeroOrDefault(op.config.OpenIDFedEntityStatementSigAlgs, []goidc.SignatureAlgorithm{defaultOpenIDFedSigAlg})
		op.config.OpenIDFedTrustMarkSigAlgs = nonZeroOrDefault(op.config.OpenIDFedTrustMarkSigAlgs, op.config.OpenIDFedEntityStatementSigAlgs)
		op.config.OpenIDFedTrustChainMaxDepth = nonZeroOrDefault(op.config.OpenIDFedTrustChainMaxDepth, defaultOpenIDFedTrustChainMaxDepth)
		op.config.OpenIDFedClientRegTypes = nonZeroOrDefault(op.config.OpenIDFedClientRegTypes, []goidc.ClientRegistrationType{defaultOpenIDFedRegType})
		if slices.Contains(op.config.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
			op.config.OpenIDFedRegistrationEndpoint = nonZeroOrDefault(op.config.OpenIDFedRegistrationEndpoint, defaultEndpointOpenIDFederationRegistration)
		}
	}

	if op.config.LogoutIsEnabled {
		op.config.LogoutSessionManager = nonZeroOrDefault(op.config.LogoutSessionManager, goidc.LogoutSessionManager(storage.NewLogoutSessionManager(defaultStorageMaxSize)))
		op.config.LogoutEndpoint = nonZeroOrDefault(op.config.LogoutEndpoint, defaultEndpointEndSession)
		op.config.LogoutSessionTimeoutSecs = nonZeroOrDefault(op.config.LogoutSessionTimeoutSecs, defaultLogoutSessionTimeoutSecs)
	}

	if op.config.SSFIsEnabled {
		ssfManager := ssf.NewEventManager(defaultStorageMaxSize)
		op.config.SSFJWKSEndpoint = nonZeroOrDefault(op.config.SSFJWKSEndpoint, defaultEndpointSSFJWKS)
		op.config.SSFConfigurationEndpoint = nonZeroOrDefault(op.config.SSFConfigurationEndpoint, defaultEndpointSSFConfiguration)
		op.config.SSFEventStreamManager = nonZeroOrDefault(op.config.SSFEventStreamManager, goidc.SSFEventStreamManager(ssfManager))
		op.config.SSFSignatureAlgorithm = nonZeroOrDefault(op.config.SSFSignatureAlgorithm, defaultSSFSigAlg)
		if op.config.SSFIsStatusManagementEnabled {
			op.config.SSFIsStatusManagementEnabled = true
			op.config.SSFStatusEndpoint = nonZeroOrDefault(op.config.SSFStatusEndpoint, defaultEndpointSSFStatus)
			op.config.SSFEventStreamManager = nonZeroOrDefault(op.config.SSFEventStreamManager, goidc.SSFEventStreamManager(ssfManager))
		}
		if op.config.SSFIsSubjectManagementEnabled {
			op.config.SSFIsSubjectManagementEnabled = true
			op.config.SSFAddSubjectEndpoint = nonZeroOrDefault(op.config.SSFAddSubjectEndpoint, defaultEndpointSSFAddSubject)
			op.config.SSFRemoveSubjectEndpoint = nonZeroOrDefault(op.config.SSFRemoveSubjectEndpoint, defaultEndpointSSFRemoveSubject)
			op.config.SSFEventStreamSubjectManager = nonZeroOrDefault(op.config.SSFEventStreamSubjectManager, goidc.SSFEventStreamSubjectManager(ssfManager))
		}
		if slices.Contains(op.config.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll) {
			op.config.SSFPollingEndpoint = nonZeroOrDefault(op.config.SSFPollingEndpoint, defaultEndpointSSFPolling)
			op.config.SSFEventPollManager = nonZeroOrDefault(op.config.SSFEventPollManager, goidc.SSFEventPollManager(ssfManager))
		}
		if op.config.SSFIsVerificationEnabled {
			op.config.SSFVerificationEndpoint = nonZeroOrDefault(op.config.SSFVerificationEndpoint, defaultEndpointSSFVerification)
			op.config.SSFEventStreamVerificationManager = nonZeroOrDefault(op.config.SSFEventStreamVerificationManager, goidc.SSFEventStreamVerificationManager(ssfManager))
		}
	}

	return nil
}

func (op *Provider) validate() error {
	return runValidations(op.config, validateTokenBinding)
}

// nonZeroOrDefault returns the first argument "s1" if it is non-nil and non-zero.
// Otherwise, it returns the second argument "s2" as the default value.
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
