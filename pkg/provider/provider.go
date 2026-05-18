package provider

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/federation"
	"github.com/luikyv/go-oidc/internal/logout"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/ssf"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Provider struct {
	config                     oidc.Configuration
	profileValidationIsEnabled bool
}

// New creates a new openid provider.
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
//   - ID tokens are signed using [defaultAsymmetricSigAlg]. Ensure a JWK supporting RS256 is
//     available in the server's JWKS.
//     This algorithm can be overridden with [WithIDTokenSignatureAlgs].
//   - Access tokens are issued as opaque tokens.
func New(issuer string, manager goidc.GrantManager, jwksFunc goidc.JWKSFunc, opts ...Option) (*Provider, error) {
	op := &Provider{
		config: oidc.Configuration{
			GrantManager: manager,
			Host:         issuer,
			JWKSFunc:     jwksFunc,
		},
	}

	for _, opt := range opts {
		if err := opt(op); err != nil {
			return nil, err
		}
	}

	if err := op.validate(); err != nil {
		return nil, err
	}

	op.setDefaults()

	if !op.profileValidationIsEnabled {
		return op, nil
	}

	if err := op.validateProfile(); err != nil {
		return nil, err
	}

	return op, nil
}

func (op *Provider) validate() error {
	if slices.Contains(op.config.SubIdentifierTypes, goidc.SubIdentifierPairwise) && op.config.PairwiseSubjectFunc == nil {
		return fmt.Errorf("pairwise subject identifier type is enabled but the pairwise func is not set, see %s", funcName(WithPairwiseSubjectFunc))
	}

	if !op.config.MTLSIsEnabled && slices.ContainsFunc(op.config.TokenAuthnMethods, func(method goidc.AuthnMethod) bool {
		return method == goidc.AuthnMethodTLS || method == goidc.AuthnMethodSelfSignedTLS
	}) {
		return errors.New("mtls must be enabled for tls_client_aut or self_signed_tls_client_auth")
	}

	if op.config.TokenBindingIsRequired && !op.config.DPoPIsEnabled && !op.config.MTLSTokenBindingIsEnabled {
		return errors.New("either dpop or tls binding must be enabled if sender constraining tokens is required")
	}

	if op.config.PARIsEnabled && !slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) {
		return errors.New("par cannot be enabled without authorization code grant")
	}

	return nil
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
	middlewares = append(middlewares, cacheControlMiddleware)
	discovery.RegisterHandlers(mux, &op.config, middlewares...)
	token.RegisterHandlers(mux, &op.config, middlewares...)
	authorize.RegisterHandlers(mux, &op.config, middlewares...)
	userinfo.RegisterHandlers(mux, &op.config, middlewares...)
	dcr.RegisterHandlers(mux, &op.config, middlewares...)
	federation.RegisterHandlers(mux, &op.config, middlewares...)
	logout.RegisterHandlers(mux, &op.config, middlewares...)
	ssf.RegisterHandlers(mux, &op.config, middlewares...)
	vc.RegisterHandlers(mux, &op.config, middlewares...)
}

func (op *Provider) Run(address string, middlewares ...goidc.MiddlewareFunc) error {
	server := &http.Server{
		Addr:        address,
		Handler:     op.Handler(middlewares...),
		ReadTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func (op *Provider) Client(ctx context.Context, id string) (*goidc.Client, error) {
	return client.Client(oidc.NewContext(ctx, &op.config), id)
}

func (op *Provider) TokenInfo(ctx context.Context, tkn string) (goidc.TokenInfo, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.Introspect(oidcCtx, tkn)
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

	info, err := token.Introspect(ctx, accessToken)
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

// GrantCIBARequest resolves an approved CIBA request into a grant and notifies
// the client according to the delivery mode for which the auth request ID was
// issued.
// The behavior varies based on the client's token delivery mode for which the
// auth request ID was issued:
//   - "poll": No notification is sent, and no additional processing occurs.
//     There is no need to call this function for this mode.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token response is sent directly to the client's notification endpoint.
func (op *Provider) GrantCIBARequest(ctx context.Context, authReqID string) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.GrantCIBARequest(oidcCtx, authReqID)
}

// DenyCIBARequest denies a CIBA request and notifies the client according to
// the delivery mode for which the auth request ID was issued.
// The behavior varies based on the client's token delivery mode:
//   - "poll": No notification is sent, and no additional processing occurs.
//   - "ping": A ping notification is sent to the client.
//   - "push": The token failure response is sent directly to the client's
//     notification endpoint.
func (op *Provider) DenyCIBARequest(ctx context.Context, authReqID string, err goidc.Error) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return token.DenyCIBARequest(oidcCtx, authReqID, err)
}

// MakeToken generates a new access token based on the provided grant
// and stores the corresponding grant session and token.
//
// This function is intended for scenarios where a token is required for the provider itself.
func (op *Provider) MakeToken(ctx context.Context, grant *goidc.Grant) (string, error) {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	c := &goidc.Client{ID: grant.ClientID}

	if grant.ID == "" {
		grant.ID = oidcCtx.GrantID()
	}

	if grant.CreatedAt == 0 {
		grant.CreatedAt = timeutil.TimestampNow()
	}

	if err := oidcCtx.HandleGrant(grant); err != nil {
		return "", err
	}

	if err := oidcCtx.SaveGrant(grant); err != nil {
		return "", err
	}

	_, tokenValue, err := token.Issue(oidcCtx, grant, c, nil)
	return tokenValue, err
}

func (op *Provider) CIBAManager() goidc.CIBAManager {
	return op.config.CIBAManager
}

func (op *Provider) RevokeToken(ctx context.Context, tkn string) error {
	return token.Revoke(oidc.NewContext(ctx, &op.config), tkn, nil)
}

func (p *Provider) PublishSSFEvent(ctx context.Context, streamID string, event goidc.SSFEvent) error {
	oidcCtx := oidc.NewContext(ctx, &p.config)
	return ssf.PublishEvent(oidcCtx, streamID, event)
}

func (op *Provider) PublishSSFVerificationEvent(ctx context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
	oidcCtx := oidc.NewContext(ctx, &op.config)
	return ssf.PublishEvent(oidcCtx, streamID, goidc.NewSSFVerificationEvent(streamID, opts))
}

func (op *Provider) setDefaults() {
	manager := storage.NewManager(defaultStorageMaxSize)

	op.config.GrantManager = nonZeroOrDefault(op.config.GrantManager, goidc.GrantManager(manager))

	op.config.Profile = nonZeroOrDefault(op.config.Profile, goidc.ProfileOpenID)

	op.config.IDTokenDefaultSigAlg = nonZeroOrDefault(op.config.IDTokenDefaultSigAlg, defaultAsymmetricSigAlg)

	op.config.IDTokenSigAlgs = nonZeroOrDefault(op.config.IDTokenSigAlgs, []goidc.SignatureAlgorithm{defaultAsymmetricSigAlg})

	op.config.Scopes = nonZeroOrDefault(op.config.Scopes, []goidc.Scope{goidc.ScopeOpenID})

	op.config.OpaqueTokenFunc = nonZeroOrDefault(op.config.OpaqueTokenFunc, defaultOpaqueTokenFunc)

	op.config.HTTPClientFunc = nonZeroOrDefault(op.config.HTTPClientFunc, defaultHTTPClientFunc)
	op.config.TokenOptionsFunc = nonZeroOrDefault(op.config.TokenOptionsFunc, goidc.TokenOptionsFunc(defaultTokenOptionsFunc))

	op.config.VerifyClientSecretFunc = nonZeroOrDefault(op.config.VerifyClientSecretFunc, goidc.VerifyClientSecretFunc(defaultVerifyClientSecretFunc))

	op.config.ResponseModes = []goidc.ResponseMode{goidc.ResponseModeQuery, goidc.ResponseModeFragment, goidc.ResponseModeFormPost}

	op.config.SubIdentifierTypeDefault = nonZeroOrDefault(op.config.SubIdentifierTypeDefault, goidc.SubIdentifierPublic)
	op.config.SubIdentifierTypes = nonZeroOrDefault(op.config.SubIdentifierTypes, []goidc.SubIdentifierType{goidc.SubIdentifierPublic})

	op.config.ClaimTypes = nonZeroOrDefault(op.config.ClaimTypes, []goidc.ClaimType{goidc.ClaimTypeNormal})

	op.config.IDTokenLifetimeSecs = nonZeroOrDefault(op.config.IDTokenLifetimeSecs, defaultIDTokenLifetimeSecs)

	op.config.WellKnownEndpoint = nonZeroOrDefault(op.config.WellKnownEndpoint, defaultEndpointWellKnown)

	op.config.JWKSEndpoint = nonZeroOrDefault(op.config.JWKSEndpoint, defaultEndpointJSONWebKeySet)

	op.config.TokenEndpoint = nonZeroOrDefault(op.config.TokenEndpoint, defaultEndpointToken)

	op.config.AuthorizationEndpoint = nonZeroOrDefault(op.config.AuthorizationEndpoint, defaultEndpointAuthorize)

	op.config.UserInfoEndpoint = nonZeroOrDefault(op.config.UserInfoEndpoint, defaultEndpointUserInfo)

	op.config.JWTLifetimeSecs = nonZeroOrDefault(op.config.JWTLifetimeSecs, defaultJWTLifetimeSecs)
	op.config.GrantIDFunc = nonZeroOrDefault(op.config.GrantIDFunc, defaultGrantIDFunc)
	op.config.JWTIDFunc = nonZeroOrDefault(op.config.JWTIDFunc, defaultJWTIDFunc)
	op.config.AuthSessionIDFunc = nonZeroOrDefault(op.config.AuthSessionIDFunc, defaultSessionIDFunc)

	if slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) {
		op.config.AuthManager = nonZeroOrDefault(op.config.AuthManager, goidc.AuthManager(manager))
		op.config.ResponseTypes = appendIfNotIn(op.config.ResponseTypes, goidc.ResponseTypeCode)
		op.config.AuthTimeoutSecs = nonZeroOrDefault(op.config.AuthTimeoutSecs, defaultAuthnSessionTimeoutSecs)
		op.config.AuthCodeLifetimeSecs = nonZeroOrDefault(op.config.AuthCodeLifetimeSecs, defaultAuthorizationCodeLifetimeSecs)
		op.config.AuthCodeFunc = nonZeroOrDefault(op.config.AuthCodeFunc, defaultAuthCodeFunc)
		if slices.ContainsFunc(op.config.ResponseTypes, func(rt goidc.ResponseType) bool {
			return rt.IsImplicit()
		}) {
			op.config.GrantTypes = append(op.config.GrantTypes, goidc.GrantImplicit)
		}
	}

	op.config.TokenAuthnMethods = nonZeroOrDefault(op.config.TokenAuthnMethods, []goidc.AuthnMethod{goidc.AuthnMethodSecretPost})
	op.config.TokenAuthnMethodDefault = nonZeroOrDefault(op.config.TokenAuthnMethodDefault, goidc.AuthnMethodSecretPost)
	if slices.Contains(op.config.TokenAuthnMethods, goidc.AuthnMethodPrivateKeyJWT) {
		op.config.TokenAuthnPrivateKeyJWTSigAlgs = nonZeroOrDefault(op.config.TokenAuthnPrivateKeyJWTSigAlgs, []goidc.SignatureAlgorithm{defaultAsymmetricSigAlg})
	}
	if slices.Contains(op.config.TokenAuthnMethods, goidc.AuthnMethodSecretJWT) {
		op.config.TokenAuthnSecretJWTSigAlgs = nonZeroOrDefault(op.config.TokenAuthnSecretJWTSigAlgs, []goidc.SignatureAlgorithm{defaultSymmetricSigAlg})
	}

	if op.config.DCRIsEnabled {
		op.config.DCRManager = nonZeroOrDefault(op.config.DCRManager, goidc.DCRManager(manager))
		op.config.DCREndpoint = nonZeroOrDefault(op.config.DCREndpoint, defaultEndpointDynamicClient)
		op.config.DCRClientIDFunc = nonZeroOrDefault(op.config.DCRClientIDFunc, defaultClientIDFunc)
	}

	if op.config.PARIsEnabled {
		op.config.PARManager = nonZeroOrDefault(op.config.PARManager, goidc.PARManager(manager))
		op.config.PARIDFunc = nonZeroOrDefault(op.config.PARIDFunc, defaultPARIDFunc)
		op.config.PAREndpoint = nonZeroOrDefault(op.config.PAREndpoint, defaultEndpointPushedAuthorizationRequest)
		op.config.PARLifetimeSecs = nonZeroOrDefault(op.config.PARLifetimeSecs, defaultPARLifetimeSecs)
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
		op.config.JARMContentEncAlgDefault = nonZeroOrDefault(op.config.JARMContentEncAlgDefault, goidc.A128CBC_HS256)
		op.config.JARMContentEncAlgs = nonZeroOrDefault(op.config.JARMContentEncAlgs,
			[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})
	}

	if op.config.TokenIntrospectionIsEnabled {
		op.config.TokenIntrospectionEndpoint = nonZeroOrDefault(op.config.TokenIntrospectionEndpoint, defaultEndpointTokenIntrospection)
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

	if slices.Contains(op.config.GrantTypes, goidc.GrantCIBA) {
		op.config.CIBAProfile = nonZeroOrDefault(op.config.CIBAProfile, goidc.CIBAProfileOpenID)
		op.config.CIBAManager = nonZeroOrDefault(op.config.CIBAManager, goidc.CIBAManager(manager))
		op.config.CIBATokenDeliveryModes = nonZeroOrDefault(op.config.CIBATokenDeliveryModes, []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll})
		op.config.CIBAIDFunc = nonZeroOrDefault(op.config.CIBAIDFunc, defaultCIBAIDFunc)
		op.config.CIBAEndpoint = nonZeroOrDefault(op.config.CIBAEndpoint, defaultEndpointCIBA)
		op.config.CIBADefaultSessionLifetimeSecs = nonZeroOrDefault(op.config.CIBADefaultSessionLifetimeSecs, defaultCIBADefaultSessionLifetimeSecs)
		op.config.CIBAPollingIntervalSecs = nonZeroOrDefault(op.config.CIBAPollingIntervalSecs, defaultCIBAPollingIntervalSecs)
	}

	if slices.Contains(op.config.GrantTypes, goidc.GrantRefreshToken) {
		op.config.RefreshTokenManager = nonZeroOrDefault(op.config.RefreshTokenManager, goidc.RefreshTokenManager(manager))
		op.config.RefreshTokenLifetimeSecs = nonZeroOrDefault(op.config.RefreshTokenLifetimeSecs, defaultRefreshTokenLifetimeSecs)
		op.config.RefreshTokenFunc = nonZeroOrDefault(op.config.RefreshTokenFunc, defaultRefreshTokenFunc)
	}

	if slices.Contains(op.config.GrantTypes, goidc.GrantDeviceCode) {
		op.config.DeviceAuthManager = nonZeroOrDefault(op.config.DeviceAuthManager, goidc.DeviceAuthManager(manager))
		op.config.DeviceAuthEndpoint = nonZeroOrDefault(op.config.DeviceAuthEndpoint, defaultEndpointDeviceAuthorization)
		op.config.DeviceAuthVerificationEndpoint = nonZeroOrDefault(op.config.DeviceAuthVerificationEndpoint, defaultEndpointDeviceVerification)
		op.config.DeviceAuthLifetimeSecs = nonZeroOrDefault(op.config.DeviceAuthLifetimeSecs, defaultDeviceAuthLifetimeSecs)
		op.config.DeviceAuthPollingIntervalSecs = nonZeroOrDefault(op.config.DeviceAuthPollingIntervalSecs, defaultDeviceAuthPollingIntervalSecs)
		op.config.DeviceCodeFunc = nonZeroOrDefault(op.config.DeviceCodeFunc, defaultDeviceCodeFunc)
		op.config.DeviceAuthGenerateUserCodeFunc = nonZeroOrDefault(op.config.DeviceAuthGenerateUserCodeFunc, defaultGenerateUserCodeFunc())
	}

	if op.config.OpenIDFedIsEnabled {
		op.config.OpenIDFedManager = nonZeroOrDefault(op.config.OpenIDFedManager, goidc.OpenIDFedManager(manager))
		op.config.OpenIDFedEndpoint = nonZeroOrDefault(op.config.OpenIDFedEndpoint, defaultEndpointOpenIDFederation)
		op.config.OpenIDFedDefaultSigAlg = nonZeroOrDefault(op.config.OpenIDFedDefaultSigAlg, defaultAsymmetricSigAlg)
		op.config.OpenIDFedSigAlgs = nonZeroOrDefault(op.config.OpenIDFedSigAlgs, []goidc.SignatureAlgorithm{defaultAsymmetricSigAlg})
		op.config.OpenIDFedTrustChainMaxDepth = nonZeroOrDefault(op.config.OpenIDFedTrustChainMaxDepth, defaultOpenIDFedTrustChainMaxDepth)
		op.config.OpenIDFedClientRegTypes = nonZeroOrDefault(op.config.OpenIDFedClientRegTypes, []goidc.ClientRegistrationType{defaultOpenIDFedRegType})
		op.config.OpenIDFedJWKSRepresentations = nonZeroOrDefault(op.config.OpenIDFedJWKSRepresentations, []goidc.JWKSRepresentation{goidc.JWKSRepresentationURI})
		op.config.OpenIDFedEntityJWKSFunc = federation.FetchEntityConfigurationJWKS
		if slices.Contains(op.config.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
			op.config.OpenIDFedRegistrationEndpoint = nonZeroOrDefault(op.config.OpenIDFedRegistrationEndpoint, defaultEndpointOpenIDFederationRegistration)
		}
		if slices.Contains(op.config.OpenIDFedJWKSRepresentations, goidc.JWKSRepresentationSignedURI) {
			op.config.OpenIDFedSignedJWKSEndpoint = nonZeroOrDefault(op.config.OpenIDFedSignedJWKSEndpoint, defaultEndpointOpenIDFederationSignedJWKS)
		}
	}

	if op.config.LogoutIsEnabled {
		op.config.LogoutManager = nonZeroOrDefault(op.config.LogoutManager, goidc.LogoutManager(manager))
		op.config.LogoutEndpoint = nonZeroOrDefault(op.config.LogoutEndpoint, defaultEndpointEndSession)
		op.config.LogoutSessionTimeoutSecs = nonZeroOrDefault(op.config.LogoutSessionTimeoutSecs, defaultLogoutSessionTimeoutSecs)
		op.config.LogoutSessionIDFunc = nonZeroOrDefault(op.config.LogoutSessionIDFunc, defaultSessionIDFunc)
	}

	if op.config.SSFIsEnabled {
		ssfManager := ssf.NewEventManager(defaultStorageMaxSize)
		op.config.SSFJWKSEndpoint = nonZeroOrDefault(op.config.SSFJWKSEndpoint, defaultEndpointSSFJWKS)
		op.config.SSFConfigurationEndpoint = nonZeroOrDefault(op.config.SSFConfigurationEndpoint, defaultEndpointSSFConfiguration)
		op.config.SSFEventStreamManager = nonZeroOrDefault(op.config.SSFEventStreamManager, goidc.SSFEventStreamManager(ssfManager))
		if op.config.SSFIsStatusManagementEnabled {
			op.config.SSFStatusEndpoint = nonZeroOrDefault(op.config.SSFStatusEndpoint, defaultEndpointSSFStatus)
			op.config.SSFEventStreamManager = nonZeroOrDefault(op.config.SSFEventStreamManager, goidc.SSFEventStreamManager(ssfManager))
		}
		if op.config.SSFIsSubjectManagementEnabled {
			op.config.SSFAddSubjectEndpoint = nonZeroOrDefault(op.config.SSFAddSubjectEndpoint, defaultEndpointSSFAddSubject)
			op.config.SSFRemoveSubjectEndpoint = nonZeroOrDefault(op.config.SSFRemoveSubjectEndpoint, defaultEndpointSSFRemoveSubject)
		}
		if slices.Contains(op.config.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll) {
			op.config.SSFPollingEndpoint = nonZeroOrDefault(op.config.SSFPollingEndpoint, defaultEndpointSSFPolling)
			op.config.SSFEventPollManager = nonZeroOrDefault(op.config.SSFEventPollManager, goidc.SSFEventPollManager(ssfManager))
		}
		if op.config.SSFIsVerificationEnabled {
			op.config.SSFVerificationEndpoint = nonZeroOrDefault(op.config.SSFVerificationEndpoint, defaultEndpointSSFVerification)
			op.config.SSFScheduleVerificationEventFunc = nonZeroOrDefault(op.config.SSFScheduleVerificationEventFunc, ssfManager.ScheduleVerificationEvent)
		}
	}

	if op.config.RARIsEnabled {
		op.config.RARCompareDetailsFunc = nonZeroOrDefault(op.config.RARCompareDetailsFunc, defaultCompareAuthDetailsFunc)
	}

}

func (op *Provider) validateProfile() error {
	if op.config.Profile == goidc.ProfileFAPI1 {
		for _, method := range op.config.TokenAuthnMethods {
			if !slices.Contains([]goidc.AuthnMethod{
				goidc.AuthnMethodPrivateKeyJWT,
				goidc.AuthnMethodSecretJWT,
				goidc.AuthnMethodTLS,
				goidc.AuthnMethodNone,
			}, method) {
				return fmt.Errorf("[FAPI 1.0 5.2.2] %s is not a valid authentication method", method)
			}
		}
	}

	if op.config.Profile == goidc.ProfileFAPI2 {
		if slices.Contains(op.config.GrantTypes, goidc.GrantImplicit) {
			return errors.New("[FAPI 2.0 5.3.1] implicit grant is not allowed")
		}

		if !op.config.TokenBindingIsRequired && !op.config.DPoPIsRequired && !op.config.MTLSTokenBindingIsRequired {
			return errors.New("[FAPI 2.0 5.3.1] sender-constrained access tokens must be required")
		}

		if !slices.Contains(op.config.TokenAuthnMethods, goidc.AuthnMethodPrivateKeyJWT) && !slices.Contains(op.config.TokenAuthnMethods, goidc.AuthnMethodTLS) {
			return errors.New("[FAPI 2.0 5.3.1] only private_key_jwt or tls_client_auth are allowed")
		}

		for _, method := range op.config.TokenAuthnMethods {
			if !slices.Contains([]goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodTLS}, method) {
				return fmt.Errorf("[FAPI 2.0 5.3.1] %s is not a valid authentication method", method)
			}
		}

		if op.config.AuthCodeLifetimeSecs > 60 {
			return errors.New("[FAPI 2.0 5.3.1] authorization code lifetime must be less than 60 seconds")
		}

		if !slices.Contains(op.config.GrantTypes, goidc.GrantAuthorizationCode) {
			return errors.New("[FAPI 2.0 5.3.1] authorization_code grant must be required")
		}

		if !op.config.PARIsRequired {
			return errors.New("[FAPI 2.0 5.3.1] pushed authorization request must be required")
		}

		if !op.config.PKCEIsRequired {
			return errors.New("[FAPI 2.0 5.3.1] pkce must be required")
		}

		if slices.ContainsFunc(op.config.PKCEChallengeMethods, func(method goidc.CodeChallengeMethod) bool {
			return method != goidc.CodeChallengeMethodSHA256
		}) {
			return errors.New("[FAPI 2.0 5.3.1] only pkce S256 code challenge method must be available")
		}

		if !op.config.IssuerRespParamIsEnabled {
			return errors.New("[FAPI 2.0 5.3.1] pkce must be enabled")
		}

		if op.config.PARLifetimeSecs > 600 {
			return errors.New("[FAPI 2.0 5.3.1] par request_uri lifetime must be less than 600 seconds")
		}
	}

	return nil
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

func funcName(f any) string {
	parts := strings.Split(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(), "/")
	return parts[len(parts)-1]
}

const (
	defaultStorageMaxSize = 100

	defaultAuthnSessionTimeoutSecs        = 1800 // 30 minutes.
	defaultIDTokenLifetimeSecs            = 600
	defaultTokenLifetimeSecs              = 300
	defaultJWTLifetimeSecs                = 600
	defaultLogoutSessionTimeoutSecs       = 1800 // 30 minutes.
	defaultPARLifetimeSecs                = 60   // 1 minute.
	defaultRefreshTokenLifetimeSecs       = 600
	defaultCIBADefaultSessionLifetimeSecs = 60
	defaultCIBAPollingIntervalSecs        = 5
	defaultDeviceAuthLifetimeSecs         = 300 // 5 minutes.
	defaultDeviceAuthPollingIntervalSecs  = 5
	defaultAuthorizationCodeLifetimeSecs  = 60

	defaultAsymmetricSigAlg            = goidc.RS256
	defaultSymmetricSigAlg             = goidc.HS256
	defaultOpenIDFedTrustChainMaxDepth = 5
	defaultOpenIDFedRegType            = goidc.ClientRegistrationTypeAutomatic

	defaultEndpointWellKnown                    = "/.well-known/openid-configuration"
	defaultEndpointJSONWebKeySet                = "/jwks"
	defaultEndpointPushedAuthorizationRequest   = "/par"
	defaultEndpointAuthorize                    = "/authorize"
	defaultEndpointToken                        = "/token"
	defaultEndpointUserInfo                     = "/userinfo"
	defaultEndpointDynamicClient                = "/register"
	defaultEndpointTokenIntrospection           = "/introspect"
	defaultEndpointTokenRevocation              = "/revoke"
	defaultEndpointCIBA                         = "/bc-authorize"
	defaultEndpointOpenIDFederation             = "/.well-known/openid-federation"
	defaultEndpointOpenIDFederationRegistration = "/federation/register"
	defaultEndpointOpenIDFederationSignedJWKS   = "/signed-jwks"
	defaultEndpointEndSession                   = "/logout"
	defaultEndpointSSFJWKS                      = "/ssf/jwks"
	defaultEndpointSSFConfiguration             = "/ssf/stream"
	defaultEndpointSSFStatus                    = "/ssf/status"
	defaultEndpointSSFAddSubject                = "/ssf/subject:add"
	defaultEndpointSSFRemoveSubject             = "/ssf/subject:remove"
	defaultEndpointSSFVerification              = "/ssf/verify"
	defaultEndpointSSFPolling                   = "/ssf/poll"
	defaultEndpointDeviceAuthorization          = "/device_authorization"
	defaultEndpointDeviceVerification           = "/device"
)

func defaultTokenOptionsFunc(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
	return goidc.NewOpaqueTokenOptions(defaultTokenLifetimeSecs)
}

func defaultOpaqueTokenFunc(_ context.Context, _ *goidc.Grant) string {
	return strutil.Random(50)
}

func defaultRefreshTokenFunc(_ context.Context) string {
	return strutil.Random(100)
}

func defaultHTTPClientFunc(_ context.Context) *http.Client {
	return http.DefaultClient
}

func defaultAuthCodeFunc(_ context.Context) string {
	return strutil.Random(30)
}

func defaultPARIDFunc(_ context.Context) string {
	return strutil.Random(30)
}

func defaultCIBAIDFunc(_ context.Context) string {
	return strutil.Random(50)
}

func defaultDeviceCodeFunc(_ context.Context) string {
	return strutil.Random(30)
}

func defaultVerifyClientSecretFunc(_ context.Context, stored, presented string) error {
	if subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) != 1 {
		return errors.New("invalid client secret")
	}
	return nil
}

func defaultCompareAuthDetailsFunc(_ context.Context, requested, granted []goidc.AuthDetail) error {
	if !reflect.DeepEqual(requested, granted) {
		return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details")
	}
	return nil
}

func defaultGenerateUserCodeFunc() goidc.RandomFunc {
	// [RFC 8628 §6.1].
	charset := "BCDFGHJKLMNPQRSTVWXZ"
	length := 8
	return func(_ context.Context) string {
		result := strings.Builder{}
		charsetLength := big.NewInt(int64(length))
		for range length {
			n, err := rand.Int(rand.Reader, charsetLength)
			if err != nil {
				panic(err)
			}
			result.WriteByte(charset[n.Int64()])
		}
		return result.String()
	}
}

func defaultClientIDFunc(ctx context.Context) string {
	return uuid.NewString()
}

func defaultGrantIDFunc(_ context.Context) string {
	return uuid.NewString()
}

func defaultJWTIDFunc(_ context.Context) string {
	return uuid.NewString()
}

func defaultSessionIDFunc(_ context.Context) string {
	return uuid.NewString()
}

func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid caching.
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
