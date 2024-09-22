package provider

import (
	"errors"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *provider) error

// WithClientStorage replaces the default client storage which keeps the clients
// stored in memory.
func WithClientStorage(
	storage goidc.ClientManager,
) ProviderOption {
	return func(p *provider) error {
		p.config.ClientManager = storage
		return nil
	}
}

// WithAuthnSessionStorage replaces the default authn session storage which
// keeps the authn sessions stored in memory.
func WithAuthnSessionStorage(
	storage goidc.AuthnSessionManager,
) ProviderOption {
	return func(p *provider) error {
		p.config.AuthnSessionManager = storage
		return nil
	}
}

// WithGrantSessionStorage replaces the default grant session storage which
// keeps the authn sessions stored in memory.
func WithGrantSessionStorage(
	storage goidc.GrantSessionManager,
) ProviderOption {
	return func(p *provider) error {
		p.config.GrantSessionManager = storage
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
// [defaultEndpointJSONWebKeySet].
func WithJWKSEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointJWKS = endpoint
		return nil
	}
}

// WithTokenEndpoint overrides the default value for the authorization
// endpoint which is [defaultEndpointToken].
func WithTokenEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointToken = endpoint
		return nil
	}
}

// WithAuthorizeEndpoint overrides the default value for the token endpoint
// which is [defaultEndpointAuthorize].
func WithAuthorizeEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointAuthorize = endpoint
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is [defaultEndpointPushedAuthorizationRequest].
// To enable pushed authorization request, see [WithPAR].
func WithPAREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointPushedAuthorization = endpoint
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is [defaultEndpointDynamicClient].
// To enable dynamic client registration, see [WithDCR].
func WithDCREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointDCR = endpoint
		return nil
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is [defaultEndpointUserInfo].
func WithUserInfoEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointUserInfo = endpoint
		return nil
	}
}

// WithIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is [defaultEndpointTokenIntrospection]
// To enable token introspection, see [WithIntrospection].
func WithIntrospectionEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.EndpointIntrospection = endpoint
		return nil
	}
}

// WithClaims signals support for user claims.
// The claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared in the field "claims_supported" of the
// well known endpoint response.
// The default value for "claim_types_supported" is set to "normal".
// To defines other claim types, see [WithClaimTypes].
func WithClaims(claims ...string) ProviderOption {
	return func(p *provider) error {
		if len(claims) == 0 {
			return errors.New("WithClaims. at least one claim must be informed")
		}
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
		return nil
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The values provided are published at "claim_types_supported".
// To add support for claims, see [WithClaims].
func WithClaimTypes(types ...goidc.ClaimType) ProviderOption {
	return func(p *provider) error {
		if len(types) == 0 {
			return errors.New("WithClaimTypes. at least one claim type must be informed")
		}
		p.config.ClaimTypes = types
		return nil
	}
}

// WithUserInfoSignatureKeyIDs set the keys available to sign the user info
// endpoint response and ID tokens.
// There should be at most one per algorithm, in other words, there shouldn't
// be two key IDs that point to two keys that have the same algorithm. This
// is because clients can choose signing keys per algorithm, e.g. a client
// can choose the key to sign its ID tokens with the attribute
// "id_token_signed_response_alg".
func WithUserInfoSignatureKeyIDs(
	defaultSigKeyID string,
	sigKeyIDs ...string,
) ProviderOption {
	if !slices.Contains(sigKeyIDs, defaultSigKeyID) {
		sigKeyIDs = append(sigKeyIDs, defaultSigKeyID)
	}

	return func(p *provider) error {
		p.config.UserDefaultSigKeyID = defaultSigKeyID
		p.config.UserSigKeyIDs = sigKeyIDs
		return nil
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// It defines how long ID tokens will be valid for when issuing them.
// The default is [defaultIDTokenLifetimeSecs].
func WithIDTokenLifetime(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.IDTokenLifetimeSecs = secs
		return nil
	}
}

// WithUserInfoEncryption allows encryption of ID tokens and of the user info
// endpoint response.
// If none passed, the default key encryption algorithm is RSA-OAEP-256.
// The default content encryption algorithm is A128CBC-HS256.
// To make available more content encryption algorithms, see
// [WithUserInfoContentEncryptionAlgs].
// Clients can choose the encryption algorithms for ID tokens by informing the
// attributes "id_token_encrypted_response_alg" and "id_token_encrypted_response_enc".
// As for the encryption of the userinfo endpoint response, the attributes are
// "userinfo_signed_response_alg" and "userinfo_encrypted_response_alg".
func WithUserInfoEncryption(keyEncAlgs ...jose.KeyAlgorithm) ProviderOption {

	if len(keyEncAlgs) == 0 {
		keyEncAlgs = append(keyEncAlgs, jose.RSA_OAEP_256)
	}

	return func(p *provider) error {
		p.config.UserEncIsEnabled = true
		p.config.UserKeyEncAlgs = keyEncAlgs
		p.config.UserDefaultContentEncAlg = jose.A128CBC_HS256
		p.config.UserContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithUserInfoContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enabled encryption of user information, see [WithUserInfoEncryption].
func WithUserInfoContentEncryptionAlgs(
	defaultAlg jose.ContentEncryption,
	algs ...jose.ContentEncryption,
) ProviderOption {
	if !slices.Contains(algs, defaultAlg) {
		algs = append(algs, defaultAlg)
	}

	return func(p *provider) error {
		p.config.UserDefaultContentEncAlg = defaultAlg
		p.config.UserContentEncAlgs = algs
		return nil
	}
}

// WithDCR allows clients to be registered dynamically.
// handler is executed during registration and update of the client to
// perform custom validations (e.g. validate the initial access token) or set
// default values (e.g. set the default scopes).
// To make registration access tokens rotate, see [WithDCRTokenRotation].
func WithDCR(
	handler goidc.HandleDynamicClientFunc,
) ProviderOption {
	return func(p *provider) error {
		p.config.DCRIsEnabled = true
		p.config.HandleDynamicClientFunc = handler
		return nil
	}
}

// WithDCRTokenRotation makes the registration access token rotate during client
// update requests.
// To enable dynamic client registration, see [WithDCR].
func WithDCRTokenRotation() ProviderOption {
	return func(p *provider) error {
		p.config.DCRTokenRotationIsEnabled = true
		return nil
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// The default refresh token lifetime is [defaultRefreshTokenLifetimeSecs] and
// the default logic to issue refresh token is [defaultIssueRefreshTokenFunc].
func WithRefreshTokenGrant() ProviderOption {
	return func(p *provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes,
			goidc.GrantRefreshToken)
		p.config.RefreshTokenLifetimeSecs = defaultRefreshTokenLifetimeSecs
		p.config.ShouldIssueRefreshTokenFunc = defaultShouldIssueRefreshTokenFunc()
		return nil
	}
}

// WithShouldIssueRefreshTokenFunc overrides the default logic to issue refresh
// tokens with is defined at [defaultShouldIssueRefreshTokenFunc].
// For more info, see: [WithRefreshTokenGrant].
func WithShouldIssueRefreshTokenFunc(f goidc.ShouldIssueRefreshTokenFunc) ProviderOption {
	return func(p *provider) error {
		p.config.ShouldIssueRefreshTokenFunc = f
		return nil
	}
}

// WithRefreshTokenLifetimeSecs defines how long refresh token will be valid for
// when issuing them.
// It overrides the default lifetime which is [defaultRefreshTokenLifetimeSecs].
// To enable the refresh token grant, see [WithRefreshTokenGrant].
func WithRefreshTokenLifetimeSecs(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.RefreshTokenLifetimeSecs = secs
		return nil
	}
}

// WithRefreshTokenRotation causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
// To enable the refresh token grant, see [WithRefreshTokenGrant].
func WithRefreshTokenRotation() ProviderOption {
	return func(p *provider) error {
		p.config.RefreshTokenRotationIsEnabled = true
		return nil
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all
// the authorization requests.
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

// WithHandleGrantFunc defines a function executed everytime a new grant is created.
// It can be used to perform validations or change the grant information before
// issuing a new access token.
func WithHandleGrantFunc(grantHandler goidc.HandleGrantFunc) ProviderOption {
	return func(p *provider) error {
		p.config.HandleGrantFunc = grantHandler
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
// The scope openid is required, so it will be added in case scopes doesn't
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
// By default, request URI's are valid for [defaultPARLifetimeSecs].
func WithPAR() ProviderOption {
	return func(p *provider) error {
		p.config.PARIsEnabled = true
		p.config.PARLifetimeSecs = defaultPARLifetimeSecs
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
// For more info, see [WithPAR].
func WithPARRequired() ProviderOption {
	return func(p *provider) error {
		p.config.PARIsRequired = true
		return WithPAR()(p)
	}
}

// WithPARLifetimeSecs overrides the default lifetime of request URI's which is
// [defaultPARLifetimeSecs].
// To enable pushed authorization request, see [WithPAR].
func WithPARLifetimeSecs(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.PARLifetimeSecs = secs
		return nil
	}
}

// WithUnregisteredRedirectURIsForPAR allows clients to inform unregistered
// redirect URIs during request to pushed authorization endpoint.
// To enable pushed authorization request, see [WithPAR].
func WithUnregisteredRedirectURIsForPAR() ProviderOption {
	return func(p *provider) error {
		p.config.PARAllowUnregisteredRedirectURI = true
		return nil
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
// If no algorithm is informed, the default is RS256.
// Clients can choose the signing algorithm by setting the attribute
// "request_object_signing_alg".
// By default, the max difference between "iat" and "exp" of request objects is
// set to [defaultJWTLifetimeSecs].
func WithJAR(
	algs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(algs) == 0 {
		algs = append(algs, jose.RS256)
	}

	return func(p *provider) error {
		p.config.JARIsEnabled = true
		p.config.JARLifetimeSecs = defaultJWTLifetimeSecs
		p.config.JARLeewayTimeSecs = defaultJWTLeewayTimeSecs
		p.config.JARSigAlgs = algs
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
// For more info, see [WithJAR].
func WithJARRequired(
	algs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.JARIsRequired = true
		return WithJAR(algs...)(p)
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
// keyEncIDs defines the keys available for clients to encrypt the request object.
// The default content encryption algorithm is A128CBC-HS256.
// Clients can inform previously the encryption algorithms they must use with
// the attributes "request_object_encryption_alg" and
// "request_object_encryption_enc"
// To enable JAR, see [WithJAR].
func WithJAREncryption(
	keyEncIDs ...string,
) ProviderOption {
	return func(p *provider) error {
		if len(keyEncIDs) == 0 {
			return errors.New("at least one key id must be informed for jar encryption")
		}
		p.config.JAREncIsEnabled = true
		p.config.JARKeyEncIDs = keyEncIDs
		p.config.JARDefaultContentEncAlg = jose.A128CBC_HS256
		p.config.JARContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithJARContentEncryptionAlgs overrides the default content encryption
// algorithm for request objects which is A128CBC-HS256.
// To enable JAR encryption, see [WithJAREncryption].
func WithJARContentEncryptionAlgs(
	defaultAlg jose.ContentEncryption,
	algs ...jose.ContentEncryption,
) ProviderOption {
	if !slices.Contains(algs, defaultAlg) {
		algs = append(algs, defaultAlg)
	}

	return func(p *provider) error {
		p.config.JARDefaultContentEncAlg = defaultAlg
		p.config.JARContentEncAlgs = algs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// defaultSigKeyID and sigKeyIDs define the keys available to sign the response
// object.
// Clients can choose the algorithm by setting the attribute
// "authorization_signed_response_alg".
// By default, the lifetime of a response object is [defaultJWTLifetimeSecs].
func WithJARM(
	defaultSigKeyID string,
	sigKeyIDs ...string,
) ProviderOption {
	if !slices.Contains(sigKeyIDs, defaultSigKeyID) {
		sigKeyIDs = append(sigKeyIDs, defaultSigKeyID)
	}

	return func(p *provider) error {
		p.config.JARMIsEnabled = true
		p.config.ResponseModes = append(
			p.config.ResponseModes,
			goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT,
			goidc.ResponseModeFragmentJWT,
			goidc.ResponseModeFormPostJWT,
		)
		p.config.JARMLifetimeSecs = defaultJWTLifetimeSecs
		p.config.JARMDefaultSigKeyID = defaultSigKeyID
		p.config.JARMSigKeyIDs = sigKeyIDs
		return nil
	}
}

// WithJARMLifetimeSecs defines when response objects will expiry after issuing
// them.
// The default lifetime is [defaultJWTLifetimeSecs].
// To enabled JARM, see [WithJARM].
func WithJARMLifetimeSecs(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.JARMLifetimeSecs = secs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted
// JWTs.
// If none passed, the default key encryption is RSA-OAEP-256.
// The default content encryption algorithm is A128CBC-HS256.
// Clients can choose the encryption algorithms by setting the attributes
// "authorization_encrypted_response_al" and "authorization_encrypted_response_enc".
// To enabled JARM, see [WithJARM].
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

// WithJARMContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enabled JARM encryption, see [WithJARM].
func WithJARMContentEncryptionAlgs(
	defaultAlg jose.ContentEncryption,
	algs ...jose.ContentEncryption,
) ProviderOption {
	if !slices.Contains(algs, defaultAlg) {
		algs = append(algs, defaultAlg)
	}

	return func(p *provider) error {
		p.config.JARMDefaultContentEncAlg = defaultAlg
		p.config.JARMContentEncAlgs = algs
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

// WithPrivateKeyJWTAuthn allows private key jwt client authentication.
// If no algorithm is specified, the default is RS256.
// Clients can inform previously the algorithm they must use to sign assertions
// with the attribute "token_endpoint_auth_signing_alg".
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

// WithBasicSecretAuthn allows client secret jwt client authentication.
// If no algorithm is specified, the default is HS256.
// Clients can inform previously the algorithm they must use to sign assertions
// with the attribute "token_endpoint_auth_signing_alg".
func WithSecretJWTAuthn(
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(sigAlgs) == 0 {
		sigAlgs = append(sigAlgs, jose.HS256)
	}

	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(
			p.config.ClientAuthnMethods,
			goidc.ClientAuthnSecretJWT,
		)
		p.config.ClientSecretJWTSigAlgs = sigAlgs
		return nil
	}
}

// WithAssertionLifetime defines a maximum threshold for the difference between
// issuance and expiry time of client assertions.
func WithAssertionLifetime(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.AssertionLifetimeSecs = secs
		return nil
	}
}

// WithTLSAuthn allows tls client authentication.
// To enable MTLS, see [WithMTLS].
func WithTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods,
			goidc.ClientAuthnTLS)
		return nil
	}
}

// WithSelfSignedTLSAuthn allows self signed tls client authentication.
// To enable MTLS, see [WithMTLS].
func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods,
			goidc.ClientAuthnSelfSignedTLS)
		return nil
	}
}

// WithNoneAuthn allows none client authentication.
func WithNoneAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthnMethods = append(p.config.ClientAuthnMethods,
			goidc.ClientAuthnNone)
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
			return errors.New("WithAuthorizationDetails. at least one authorization detail type must be informed")
		}

		p.config.AuthDetailsIsEnabled = true
		p.config.AuthDetailTypes = types
		return nil
	}
}

// WithMTLS allows requests to be established with mutual TLS.
// The default logic to extract the client certificate is using the header
// [goidc.HeaderClientCert]. For more info, see [defaultClientCertFunc].
// The client certificate logic can be overriden with [WithClientCertFunc].
func WithMTLS(
	host string,
) ProviderOption {
	return func(p *provider) error {
		p.config.MTLSIsEnabled = true
		p.config.MTLSHost = host
		p.config.ClientCertFunc = defaultClientCertFunc()
		return nil
	}
}

// WithClientCertFunc overrides the default logic to fetch a client
// certificate during requests.
// The default logic is defined at [defaultClientCertFunc].
// To enable MTLS, see [WithMTLS].
func WithClientCertFunc(
	f goidc.ClientCertFunc,
) ProviderOption {
	return func(p *provider) error {
		p.config.ClientCertFunc = f
		return nil
	}
}

// WithTLSCertTokenBinding makes requests to /token return tokens bound to the
// client certificate if any is sent.
// To enable MTLS, see [WithMTLS].
func WithTLSCertTokenBinding() ProviderOption {
	return func(p *provider) error {
		p.config.MTLSTokenBindingIsEnabled = true
		return nil
	}
}

// WithTLSCertTokenBindingRequired makes requests to /token return tokens bound to the
// client certificate.
// For more info, see [WithTLSCertTokenBinding].
func WithTLSCertTokenBindingRequired() ProviderOption {
	return func(p *provider) error {
		p.config.MTLSTokenBindingIsRequired = true
		return WithTLSCertTokenBinding()(p)
	}
}

// WithDPoP enables proof of possesion with DPoP.
// It requires tokens to be bound to a cryptographic key generated by the client.
// If not algorithm is informed, the default is RS256.
// By default, the max difference between the claims "iat" and "exp" of DPoP
// JWTs is set to [defaultJWTLifetimeSecs]
func WithDPoP(
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(sigAlgs) == 0 {
		sigAlgs = append(sigAlgs, jose.RS256)
	}

	return func(p *provider) error {
		p.config.DPoPIsEnabled = true
		p.config.DPoPLifetimeSecs = defaultJWTLifetimeSecs
		p.config.DPoPLeewayTimeSecs = defaultJWTLeewayTimeSecs
		p.config.DPoPSigAlgs = sigAlgs
		return nil
	}
}

// WithDPoPRequired makes DPoP required.
// For more information, see [WithDPoP].
func WithDPoPRequired(
	sigAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.DPoPIsRequired = true
		return WithDPoP(sigAlgs...)(p)
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required in order to issue an access token to a client.
// For more info, see [WithTLSCertTokenBinding] and [WithDPoP].
func WithTokenBindingRequired() ProviderOption {
	return func(p *provider) error {
		p.config.TokenBindingIsRequired = true
		return nil
	}
}

// WithIntrospection allows authorized clients to introspect tokens.
// A client can only introspect tokens if it has the grant type
// [goidc.GrantIntrospection].
func WithIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) ProviderOption {
	return func(p *provider) error {
		if len(clientAuthnMethods) == 0 {
			return errors.New("WithIntrospection. at least one client authentication mechanism must be informed")
		}
		p.config.IntrospectionIsEnabled = true
		p.config.IntrospectionClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
		return nil
	}
}

// WithPKCE makes proof key for code exchange available to clients.
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
// These values will be published as are in the well know endpoint response.
func WithACRs(
	values ...goidc.ACR,
) ProviderOption {
	return func(p *provider) error {
		if len(values) == 0 {
			return errors.New("WithACRs. at least one acr must be informed")
		}

		p.config.ACRs = values
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the
// authorization endpoint.
// These values will be published as are in the well known endpoint response.
func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *provider) error {
		if len(values) == 0 {
			return errors.New("WithDisplayValues. at least one value must be informed")
		}

		p.config.DisplayValues = values
		return nil
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
// This defines how long an authorization request may last.
// The default is [defaultAuthnSessionTimeoutSecs].
func WithAuthenticationSessionTimeout(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.AuthnSessionTimeoutSecs = secs
		return nil
	}
}

// WithStaticClient adds a static client to the provider.
// The static clients are kept in memory only and are checked before consulting
// the client manager.
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
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithRenderErrorFunc(render goidc.RenderErrorFunc) ProviderOption {
	return func(p *provider) error {
		p.config.RenderErrorFunc = render
		return nil
	}
}

// WithHandleErrorFunc defines a handler to be executed when an error happens.
// For instance, this can be used to log information about the error
func WithHandleErrorFunc(f goidc.HandleErrorFunc) ProviderOption {
	return func(p *provider) error {
		p.config.HandleErrorFunc = f
		return nil
	}
}

// WithResourceIndicators enables client to indicate which resources they intend
// to access.
func WithResourceIndicators(resources ...string) ProviderOption {
	return func(p *provider) error {
		if len(resources) == 0 {
			return errors.New("WithResourceIndicators. at least one resource indicator must be provided")
		}

		p.config.ResourceIndicatorsIsEnabled = true
		p.config.Resources = resources
		return nil
	}
}

// WithResourceIndicatorsRequired makes resource indicators required.
// For more info, see [WithResourceIndicators].
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

// WithHTTPClientFunc defines how to generate the client used to make HTTP
// requests to, for instance, a client's JWKS endpoint.
// The default behavior is to use the default HTTP client from the std library.
func WithHTTPClientFunc(f goidc.HTTPClientFunc) ProviderOption {
	return func(p *provider) error {
		p.config.HTTPClientFunc = f
		return nil
	}
}
