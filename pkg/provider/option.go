package provider

// TODO: Review defaults, params and validations.

import (
	"errors"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *provider) error

// WithStorage defines how the provider will store clients and sessions.
//
// It overrides the default storage which keeps everything in memory.
func WithStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) ProviderOption {
	return func(p *provider) error {
		p.config.ClientManager = clientManager
		p.config.AuthnSessionManager = authnSessionManager
		p.config.GrantSessionManager = grantSessionManager
		return nil
	}
}

// WithPathPrefix defines a shared prefix for all endpoints.
// When using the provider http handler directly, the path prefix must be added
// to the router.
//
//	op, err := provider.New(
//		"http://example.com",
//		jose.JSONWebKeySet{},
//		provider.WithPathPrefix("/auth"),
//	)
//	server := http.NewServeMux()
//	server.Handle("/auth/", op.Handler())
func WithPathPrefix(prefix string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointPrefix = prefix
		return nil
	}
}

// WithJWKSEndpoint overrides the default value for the jwks endpoint which is
// /jwks.
func WithJWKSEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointJWKS = endpoint
		return nil
	}
}

// WithTokenEndpoint overrides the default value for the authorization
// endpoint which is /token.
func WithTokenEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointToken = endpoint
		return nil
	}
}

// WithAuthorizeEndpoint overrides the default value for the token endpoint
// which is /authorize.
func WithAuthorizeEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointAuthorize = endpoint
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is /par.
func WithPAREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointPushedAuthorization = endpoint
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is /register.
func WithDCREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointDCR = endpoint
		return nil
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is /userinfo.
func WithUserInfoEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointUserInfo = endpoint
		return nil
	}
}

// WithIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is /introspect.
func WithIntrospectionEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointIntrospection = endpoint
		return nil
	}
}

// WithClaims signals support for custom user claims.
// These claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared with the field "claims_supported" of the
// well known endpoint response.
// The default value for "claim_types_supported" is set to "normal".
func WithClaims(claims ...string) ProviderOption {
	return func(p *provider) error {
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
		return nil
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The value provided are published at "claim_types_supported".
func WithClaimTypes(types ...goidc.ClaimType) ProviderOption {
	if len(types) == 0 {
		types = append(types, goidc.ClaimTypeNormal)
	}
	return func(p *provider) error {
		p.config.ClaimTypes = types
		return nil
	}
}

// WithUserInfoSignatureKeyIDs set the keys available to sign the user info
// endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't be
// two key IDs that point to two keys that have the same algorithm.
// This is because clients can choose signing keys per algorithm, e.g. a client
// can choose the key to sign its ID tokens with the attribute
// "id_token_signed_response_alg".
func WithUserInfoSignatureKeyIDs(
	defaultSigKeyID string,
	sigKeyIDs ...string,
) ProviderOption {
	return func(p *provider) error {
		if !slices.Contains(sigKeyIDs, defaultSigKeyID) {
			sigKeyIDs = append(
				sigKeyIDs,
				defaultSigKeyID,
			)
		}
		p.config.UserSigKeyIDs = sigKeyIDs
		return nil
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// The default is 600 seconds.
func WithIDTokenLifetime(lifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.IDTokenLifetimeSecs = lifetimeSecs
		return nil
	}
}

// WithUserInfoEncryption allows encryption of ID tokens and of the user info
// endpoint response.
// If none passed, the default key encryption is RSA-OAEP-256.
// The default content encryption algorithm is A128CBC-HS256.
func WithUserInfoEncryption(keyEncAlgs ...jose.KeyAlgorithm) ProviderOption {

	if len(keyEncAlgs) == 0 {
		keyEncAlgs = append(keyEncAlgs, jose.RSA_OAEP_256)
	}

	return func(p *provider) error {
		p.config.UserEncIsEnabled = true
		p.config.UserKeyEncAlgs = keyEncAlgs
		p.config.UserDefaultContentEncAlg = jose.A128CBC_HS256
		p.config.UserContentEncAlg = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithDCR allows clients to be registered dynamically.
//
// The handler is executed during registration and update of the client to
// perform custom validations (e.g. validate a custom property) or set default
// values (e.g. set the default scopes).
func WithDCR(
	handler goidc.HandleDynamicClientFunc,
) ProviderOption {
	return func(p *provider) error {
		p.config.DCRIsEnabled = true
		p.config.HandleDynamicClientFunc = handler
		return nil
	}
}

func WithDCRTokenRotation() ProviderOption {
	return func(p *provider) error {
		p.config.DCRTokenRotationIsEnabled = true
		return nil
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
func WithRefreshTokenGrant(
	lifetimeSecs int,
) ProviderOption {
	return func(p *provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		p.config.RefreshTokenLifetimeSecs = lifetimeSecs
		return nil
	}
}

// WithRefreshTokenRotation causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenRotation() ProviderOption {
	return func(p *provider) error {
		p.config.RefreshTokenRotationIsEnabled = true
		return nil
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all requests.
func WithOpenIDScopeRequired() ProviderOption {
	return func(p *provider) error {
		p.config.OpenIDIsRequired = true
		return nil
	}
}

// WithTokenOptions defines how access tokens are issued.
func WithTokenOptions(tokenOpts goidc.TokenOptionsFunc) ProviderOption {
	return func(p *provider) error {
		p.config.TokenOptionsFunc = tokenOpts
		return nil
	}
}

// WithImplicitGrant allows the implicit grant type and the associated
// response types.
func WithImplicitGrant() ProviderOption {
	return func(p *provider) error {
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
		return nil
	}
}

// WithScopes defines the scopes accepted by the provider.
// Since the scope openid is required, it will be added in case scopes doesn't
// contain it.
func WithScopes(scopes ...goidc.Scope) ProviderOption {
	return func(p *provider) error {
		p.config.Scopes = scopes
		// The scope openid is required to be among the scopes.
		for _, scope := range scopes {
			if scope.ID == goidc.ScopeOpenID.ID {
				return nil
			}
		}
		p.config.Scopes = append(scopes, goidc.ScopeOpenID)
		return nil
	}
}

// WithPAR allows authorization flows to start at the pushed authorization
// request endpoint.
func WithPAR(lifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.PARIsEnabled = true
		p.config.PARLifetimeSecs = lifetimeSecs
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
func WithPARRequired(lifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.PARIsRequired = true
		return WithPAR(lifetimeSecs)(p)
	}
}

// WithUnregisteredRedirectURIsDuringPAR allows clients to inform unregistered
// redirect URIs during request to pushed authorization endpoint.
// This only takes effect when PAR is enabled
func WithUnregisteredRedirectURIsDuringPAR() ProviderOption {
	return func(p *provider) error {
		p.config.PARAllowUnregisteredRedirectURI = true
		return nil
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
func WithJAR(
	lifetimeSecs int,
	algs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.JARIsEnabled = true
		p.config.JARLifetimeSecs = lifetimeSecs
		for _, jarAlgorithm := range algs {
			p.config.JARSigAlgs = append(
				p.config.JARSigAlgs,
				jose.SignatureAlgorithm(jarAlgorithm),
			)
		}
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
func WithJARRequired(
	lifetimeSecs int,
	algs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.JARIsRequired = true
		return WithJAR(lifetimeSecs, algs...)(p)
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
//
// The default content encryption algorithm is A128CBC-HS256.
func WithJAREncryption(
	// TODO: Use the first key as the default
	keyEncIDs []string,
) ProviderOption {
	return func(p *provider) error {
		p.config.JAREncIsEnabled = true
		p.config.JARKeyEncIDs = keyEncIDs
		p.config.JARDefaultContentEncAlg = jose.A128CBC_HS256
		p.config.JARContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// It enables JWT response modes.
func WithJARM(
	lifetimeSecs int,
	defaultSigKeyID string,
	sigKeyIDs ...string,
) ProviderOption {
	return func(p *provider) error {
		if !slices.Contains(sigKeyIDs, defaultSigKeyID) {
			sigKeyIDs = append(sigKeyIDs, defaultSigKeyID)
		}

		p.config.JARMIsEnabled = true
		p.config.ResponseModes = append(
			p.config.ResponseModes,
			goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT,
			goidc.ResponseModeFragmentJWT,
			goidc.ResponseModeFormPostJWT,
		)
		p.config.JARMLifetimeSecs = lifetimeSecs
		p.config.JARMDefaultSigKeyID = defaultSigKeyID
		p.config.JARMSigKeyIDs = sigKeyIDs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted
// JWTs.
//
// If none passed, the default key encryption is RSA-OAEP-256.
// The default content encryption algorithm is A128CBC-HS256.
func WithJARMEncryption(
	keyEncAlgs ...jose.KeyAlgorithm,
) ProviderOption {
	if len(keyEncAlgs) == 0 {
		keyEncAlgs = append(keyEncAlgs, jose.RSA_OAEP_256)
	}

	return func(p *provider) error {
		p.config.JARMEncIsEnabled = true
		p.config.JARMKeyEncAlgs = keyEncAlgs
		p.config.JARMDefaultContentEncAlg = jose.A128CBC_HS256
		p.config.JARMContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithBasicSecretAuthn allows secret basic client authentication.
func WithBasicSecretAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretBasic,
		)
		return nil
	}
}

// WithSecretPostAuthn allows secret post client authentication.
func WithSecretPostAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretPost,
		)
		return nil
	}
}

// WithPrivateKeyJWTAuthn allows private key jwt client authentication. If no
// algorithm is specified, the default is RS256.
func WithPrivateKeyJWTAuthn(
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(sigAlgs) == 0 {
		sigAlgs = append(sigAlgs, jose.RS256)
	}
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnPrivateKeyJWT,
		)
		p.config.PrivateKeyJWTSigAlgs = sigAlgs
		return nil
	}
}

// WithBasicSecretAuthn allows client secret jwt client authentication. If no
// algorithm is specified, the default is HS256.
func WithClientSecretJWTAuthn(
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(sigAlgs) == 0 {
		sigAlgs = append(sigAlgs, jose.HS256)
	}
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretBasic,
		)
		p.config.ClientSecretJWTSigAlgs = sigAlgs
		return nil
	}
}

// WithAssertionLifetime defines a maximum threshold for the difference between
// issuance and expiry time of client assertions.
// signatureAlgorithms defines the symmetric algorithms allowed to sign the
// assertions.
func WithAssertionLifetime(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.AssertionLifetimeSecs = secs
		return nil
	}
}

// WithTLSAuthn allows tls client authentication.
func WithTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnTLS,
		)
		return nil
	}
}

// WithSelfSignedTLSAuthn allows self signed tls client authentication.
func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSelfSignedTLS,
		)
		return nil
	}
}

// WithNoneAuthn allows none client authentication.
func WithNoneAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnNone,
		)
		return nil
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() ProviderOption {
	return func(p *provider) error {
		p.config.IssuerRespParamIsEnabled = true
		return nil
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() ProviderOption {
	return func(p *provider) error {
		p.config.ClaimsParamIsEnabled = true
		return nil
	}
}

// WithAuthorizationDetails allows clients to make rich authorization requests.
func WithAuthorizationDetails(types ...string) ProviderOption {

	return func(p *provider) error {
		if len(types) == 0 {
			return errors.New("at least one authorization detail type must be informed")
		}

		p.config.AuthDetailsIsEnabled = true
		p.config.AuthDetailTypes = types
		return nil
	}
}

// WithMTLS allows requests to be established with mutual TLS.
//
// The default logic to extract the client certificate is using the header
// [goidc.HeaderClientCertificate].
func WithMTLS(
	mtlsHost string,
) ProviderOption {
	return func(p *provider) error {
		p.config.MTLSIsEnabled = true
		p.config.MTLSHost = mtlsHost
		return nil
	}
}

// WithClientCertFunc overrides the default logic to fetch a client
// certificate during requests.
func WithClientCertFunc(
	f goidc.ClientCertFunc,
) ProviderOption {
	return func(p *provider) error {
		p.config.ClientCertFunc = f
		return nil
	}
}

// WithMTLSTokenBinding makes requests to /token return tokens bound to the
// client certificate if any is sent.
func WithMTLSTokenBinding() ProviderOption {
	return func(p *provider) error {
		p.config.MTLSTokenBindingIsEnabled = true
		return nil
	}
}

// WithDPoP enables proof of possesion with DPoP.
//
// It requires tokens to be bound to a cryptographic key generated by the client.
//
// If not algorithm is informed, the default is RS256.
func WithDPoP(
	lifetimeSecs int,
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(sigAlgs) == 0 {
		sigAlgs = append(sigAlgs, jose.RS256)
	}
	return func(p *provider) error {
		p.config.DPoPIsEnabled = true
		p.config.DPoPLifetimeSecs = lifetimeSecs
		for _, signatureAlgorithm := range sigAlgs {
			p.config.DPoPSigAlgs = append(
				p.config.DPoPSigAlgs,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
		return nil
	}
}

// WithDPoPRequired makes DPoP required.
//
// For more information, see [WithDPoP].
func WithDPoPRequired(
	lifetimeSecs int,
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.DPoPIsRequired = true
		return WithDPoP(lifetimeSecs, sigAlgs...)(p)
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required in order to issue an access token to a client.
func WithTokenBindingRequired() ProviderOption {
	return func(p *provider) error {
		p.config.TokenBindingIsRequired = true
		return nil
	}
}

// WithIntrospection allows authorized clients to introspect tokens.
func WithIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) ProviderOption {
	return func(p *provider) error {
		if len(clientAuthnMethods) == 0 {
			return errors.New("at least one client authentication mechanism must be informed for introspection")
		}
		p.config.IntrospectionIsEnabled = true
		p.config.IntrospectionClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
		return nil
	}
}

// WithPKCE makes proof key for code exchange available to clients.
//
// The first code challenged informed is used as the default.
// If no code challenge method is informed, the default is S256.
func WithPKCE(
	methods ...goidc.CodeChallengeMethod,
) ProviderOption {
	if len(methods) == 0 {
		methods = append(methods, goidc.CodeChallengeMethodSHA256)
	}
	return func(p *provider) error {
		p.config.PKCEIsEnabled = true
		p.config.PKCEDefaultChallengeMethod = methods[0]
		p.config.PKCEChallengeMethods = methods
		return nil
	}
}

// WithPKCERequired makes proof key for code exchange required.
//
// For more info, see [WithPKCE].
func WithPKCERequired(
	methods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *provider) error {
		p.config.PKCEIsRequired = true
		return WithPKCE(methods...)(p)
	}
}

// WithACRs makes available authentication context references.
//
// These values will be published as are in the well know endpoint response.
func WithACRs(
	values ...goidc.ACR,
) ProviderOption {
	return func(p *provider) error {
		p.config.ACRs = values
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the
// authorization endpoint.
//
// These values will be published as are in the well known endpoint response.
func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *provider) error {
		p.config.DisplayValues = values
		return nil
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
//
// This defines how long an authorization request may last.
func WithAuthenticationSessionTimeout(timeoutSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.AuthnSessionTimeoutSecs = timeoutSecs
		return nil
	}
}

// WithProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the
// FAPI 2.0 profile.
//
// This will also change some of the behavior of the server during runtime to be
// compliant with the FAPI 2.0.
func WithProfileFAPI2() ProviderOption {
	return func(p *provider) error {
		p.config.Profile = goidc.ProfileFAPI2
		return nil
	}
}

// WithStaticClient adds a static client to the provider.
//
// The static clients are checked before consulting the client manager.
func WithStaticClient(client *goidc.Client) ProviderOption {
	return func(p *provider) error {
		p.config.StaticClients = append(p.config.StaticClients, client)
		return nil
	}
}

// WithPolicy adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func WithPolicy(policy goidc.AuthnPolicy) ProviderOption {
	return func(p *provider) error {
		p.config.Policies = append(p.config.Policies, policy)
		return nil
	}
}

// WithAuthorizeErrorPlugin defines a handler to be executed when the
// authorization request results in error, but the error can't be redirected.
//
// This can be used to display a page with the error.
//
// The default behavior is to display a JSON with the error information to the user.
func WithRenderErrorFunc(render goidc.RenderErrorFunc) ProviderOption {
	return func(p *provider) error {
		p.config.RenderErrorFunc = render
		return nil
	}
}

func WithResourceIndicators(resources ...string) ProviderOption {
	return func(p *provider) error {
		if len(resources) == 0 {
			return errors.New("at least one resource indicator must be provided")
		}
		p.config.ResourceIndicatorsIsEnabled = true
		p.config.Resources = resources
		return nil
	}
}

func WithResourceIndicatorsRequired(resources ...string) ProviderOption {
	return func(p *provider) error {
		p.config.ResourceIndicatorsIsRequired = true
		return WithResourceIndicators(resources...)(p)
	}
}

// WithOutterAuthorizationParamsRequired enforces that the parameters required
// during /authorize must be informed as query parameters even if they were
// already sent previously during PAR or inside JAR.
func WithOutterAuthorizationParamsRequired() ProviderOption {
	return func(p *provider) error {
		p.config.OutterAuthParamsRequired = true
		return nil
	}
}
