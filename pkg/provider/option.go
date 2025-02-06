package provider

import (
	"errors"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p Provider) error

// WithClientStorage replaces the default client storage which keeps the clients
// stored in memory.
func WithClientStorage(
	storage goidc.ClientManager,
) ProviderOption {
	return func(p Provider) error {
		p.config.ClientManager = storage
		return nil
	}
}

// WithAuthnSessionStorage replaces the default authn session storage which
// keeps the authn sessions stored in memory.
func WithAuthnSessionStorage(
	storage goidc.AuthnSessionManager,
) ProviderOption {
	return func(p Provider) error {
		p.config.AuthnSessionManager = storage
		return nil
	}
}

// WithGrantSessionStorage replaces the default grant session storage which
// keeps the authn sessions stored in memory.
func WithGrantSessionStorage(
	storage goidc.GrantSessionManager,
) ProviderOption {
	return func(p Provider) error {
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
//		jwksFunc,
//		provider.WithPathPrefix("/auth"),
//	)
//	server := http.NewServeMux()
//	server.Handle("/auth/", op.Handler())
func WithPathPrefix(prefix string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointPrefix = prefix
		return nil
	}
}

// WithJWKSEndpoint overrides the default value for the jwks endpoint which is
// [defaultEndpointJSONWebKeySet].
func WithJWKSEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointJWKS = endpoint
		return nil
	}
}

// WithTokenEndpoint overrides the default value for the authorization
// endpoint which is [defaultEndpointToken].
func WithTokenEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointToken = endpoint
		return nil
	}
}

// WithAuthorizeEndpoint overrides the default value for the token endpoint
// which is [defaultEndpointAuthorize].
func WithAuthorizeEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointAuthorize = endpoint
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is [defaultEndpointPushedAuthorizationRequest].
// To enable pushed authorization request, see [WithPAR].
func WithPAREndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointPushedAuthorization = endpoint
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is [defaultEndpointDynamicClient].
// To enable dynamic client registration, see [WithDCR].
func WithDCREndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointDCR = endpoint
		return nil
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is [defaultEndpointUserInfo].
func WithUserInfoEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointUserInfo = endpoint
		return nil
	}
}

// WithTokenIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is [defaultEndpointTokenIntrospection]
// To enable token introspection, see [WithTokenIntrospection].
func WithTokenIntrospectionEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointIntrospection = endpoint
		return nil
	}
}

// WithTokenRevocationEndpoint overrides the default value for the token
// revocation endpoint which is [defaultEndpointTokenRevocation]
// To enable token revocation, see [WithTokenRevocation].
func WithTokenRevocationEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointTokenRevocation = endpoint
		return nil
	}
}

// WithCIBAEndpoint overrides the default value for the CIBA endpoint which is
// [defaultEndpointCIBA].
func WithCIBAEndpoint(endpoint string) ProviderOption {
	return func(p Provider) error {
		p.config.EndpointCIBA = endpoint
		return nil
	}
}

// WithClaims signals support for user claims.
// The claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared in the field "claims_supported" of the
// well known endpoint response.
// The default value for "claim_types_supported" is set to "normal".
// To define other claim types, see [WithClaimTypes].
func WithClaims(
	claim string,
	claims ...string,
) ProviderOption {
	claims = appendIfNotIn(claims, claim)
	return func(p Provider) error {
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
		return nil
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The values provided are published at "claim_types_supported".
// To add support for claims, see [WithClaims].
func WithClaimTypes(
	claimType goidc.ClaimType,
	claimTypes ...goidc.ClaimType,
) ProviderOption {
	claimTypes = appendIfNotIn(claimTypes, claimType)
	return func(p Provider) error {
		p.config.ClaimTypes = claimTypes
		return nil
	}
}

// WithUserInfoSignatureAlgs set the algorithms available to sign the user info
// endpoint response.
func WithUserInfoSignatureAlgs(
	defaultAlg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		p.config.UserInfoDefaultSigAlg = defaultAlg
		p.config.UserInfoSigAlgs = algs
		return nil
	}
}

// WithUserInfoEncryption allows encryption of the user info endpoint response.
// The default content encryption algorithm is A128CBC-HS256.
// To make available more content encryption algorithms, see
// [WithUserInfoContentEncryptionAlgs].
// Clients can choose the encryption algorithms for user info by informing the
// attributes "userinfo_signed_response_alg" and "userinfo_encrypted_response_alg".
func WithUserInfoEncryption(
	keyEncAlg goidc.KeyEncryptionAlgorithm,
	keyEncAlgs ...goidc.KeyEncryptionAlgorithm,
) ProviderOption {
	keyEncAlgs = appendIfNotIn(keyEncAlgs, keyEncAlg)
	return func(p Provider) error {
		p.config.UserInfoEncIsEnabled = true
		p.config.UserInfoKeyEncAlgs = keyEncAlgs
		return nil
	}
}

// WithUserInfoContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enabled encryption of user information, see [WithUserInfoEncryption].
func WithUserInfoContentEncryptionAlgs(
	defaultAlg goidc.ContentEncryptionAlgorithm,
	algs ...goidc.ContentEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		p.config.UserInfoDefaultContentEncAlg = defaultAlg
		p.config.UserInfoContentEncAlgs = algs
		return nil
	}
}

// WithUserSignatureAlgs set the algorithms available to sign ID tokens.
func WithIDTokenSignatureAlgs(
	defaultAlg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		p.config.IDTokenDefaultSigAlg = defaultAlg
		p.config.IDTokenSigAlgs = algs
		return nil
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// It defines how long ID tokens will be valid for when issuing them.
// The default is [defaultIDTokenLifetimeSecs].
func WithIDTokenLifetime(secs int) ProviderOption {
	return func(p Provider) error {
		p.config.IDTokenLifetimeSecs = secs
		return nil
	}
}

// WithIDTokenEncryption allows encryption of ID tokens.
// The default content encryption algorithm is A128CBC-HS256.
// To make available more content encryption algorithms, see
// [WithIDTokenContentEncryptionAlgs].
// Clients can choose the encryption algorithms for ID tokens by informing the
// attributes "id_token_encrypted_response_alg" and "id_token_encrypted_response_enc".
func WithIDTokenEncryption(
	keyEncAlg goidc.KeyEncryptionAlgorithm,
	keyEncAlgs ...goidc.KeyEncryptionAlgorithm,
) ProviderOption {
	keyEncAlgs = appendIfNotIn(keyEncAlgs, keyEncAlg)
	return func(p Provider) error {
		p.config.IDTokenEncIsEnabled = true
		p.config.IDTokenKeyEncAlgs = keyEncAlgs
		return nil
	}
}

// WithIDTokenContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enabled encryption of ID tokens, see [WithIDTokenEncryption].
func WithIDTokenContentEncryptionAlgs(
	defaultAlg goidc.ContentEncryptionAlgorithm,
	algs ...goidc.ContentEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		p.config.IDTokenDefaultContentEncAlg = defaultAlg
		p.config.IDTokenContentEncAlgs = algs
		return nil
	}
}

// WithDCR allows clients to be registered dynamically.
// handler is executed during registration and update of the client to
// perform custom validations (e.g. validate the initial access token) or set
// default values (e.g. set the default scopes).
// To make registration access tokens rotate, see [WithDCRTokenRotation].
func WithDCR(
	handleFunc goidc.HandleDynamicClientFunc,
	validateTokenFunc goidc.ValidateInitialAccessTokenFunc,
) ProviderOption {
	return func(p Provider) error {
		p.config.DCRIsEnabled = true
		p.config.HandleDynamicClientFunc = handleFunc
		p.config.ValidateInitialAccessTokenFunc = validateTokenFunc
		return nil
	}
}

// WithDCRTokenRotation makes the registration access token rotate during client
// update requests.
// To enable dynamic client registration, see [WithDCR].
func WithDCRTokenRotation() ProviderOption {
	return func(p Provider) error {
		p.config.DCRTokenRotationIsEnabled = true
		return nil
	}
}

// WithClientCredentialsGrant makes available the client credentials grant.
func WithClientCredentialsGrant() ProviderOption {
	return func(p Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes,
			goidc.GrantClientCredentials)
		return nil
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// The default refresh token lifetime is [defaultRefreshTokenLifetimeSecs] and
// the default logic to issue refresh token is [defaultIssueRefreshTokenFunc].
func WithRefreshTokenGrant(
	f goidc.ShouldIssueRefreshTokenFunc,
	lifetimeSecs int,
) ProviderOption {
	return func(p Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes,
			goidc.GrantRefreshToken)
		p.config.ShouldIssueRefreshTokenFunc = f
		p.config.RefreshTokenLifetimeSecs = lifetimeSecs
		return nil
	}
}

// WithRefreshTokenRotation causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
// To enable the refresh token grant, see [WithRefreshTokenGrant].
func WithRefreshTokenRotation() ProviderOption {
	return func(p Provider) error {
		p.config.RefreshTokenRotationIsEnabled = true
		return nil
	}
}

func WithCIBAGrant(
	initFunc goidc.InitBackAuthFunc,
	validateFunc goidc.ValidateBackAuthFunc,
	mode goidc.CIBATokenDeliveryMode,
	modes ...goidc.CIBATokenDeliveryMode,
) ProviderOption {
	return func(p Provider) error {
		p.config.CIBAIsEnabled = true
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantCIBA)
		p.config.CIBATokenDeliveryModels = appendIfNotIn(modes, mode)
		p.config.InitBackAuthFunc = initFunc
		p.config.ValidateBackAuthFunc = validateFunc
		p.config.CIBADefaultSessionLifetimeSecs = 60
		p.config.CIBAPollingIntervalSecs = 5
		return nil
	}
}

func WithCIBAJAR(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
		p.config.CIBAJARIsEnabled = true
		p.config.CIBAJARSigAlgs = algs
		return nil
	}
}

func WithCIBAJARRequired(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	return func(p Provider) error {
		p.config.CIBAJARIsRequired = true
		return WithJAR(alg, algs...)(p)
	}
}

func WithCIBAUserCode() ProviderOption {
	return func(p Provider) error {
		p.config.CIBAUserCodeIsEnabled = true
		return nil
	}
}

func WithCIBAPollingInterval(interval int) ProviderOption {
	return func(p Provider) error {
		p.config.CIBAPollingIntervalSecs = interval
		return nil
	}
}

func WithCIBALifetime(secs int) ProviderOption {
	return func(p Provider) error {
		p.config.CIBADefaultSessionLifetimeSecs = secs
		return nil
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all
// the authorization requests.
func WithOpenIDScopeRequired() ProviderOption {
	return func(p Provider) error {
		p.config.OpenIDIsRequired = true
		return nil
	}
}

// WithTokenOptions configures the way access tokens are issued by the provider.
//
// If pairwise subject identifiers are enabled and applicable to the subject,
// the token will be issued as an opaque token, even when the token option is set
// to issue a JWT token.
func WithTokenOptions(tokenOpts goidc.TokenOptionsFunc) ProviderOption {
	return func(p Provider) error {
		p.config.TokenOptionsFunc = tokenOpts
		return nil
	}
}

// WithHandleGrantFunc defines a function executed everytime a new grant is created.
// It can be used to perform validations or change the grant information before
// issuing a new access token.
func WithHandleGrantFunc(grantHandler goidc.HandleGrantFunc) ProviderOption {
	return func(p Provider) error {
		p.config.HandleGrantFunc = grantHandler
		return nil
	}
}

// WithAuthorizationCodeGrant allows the authorization_code grant type and the
// associated response types.
func WithAuthorizationCodeGrant() ProviderOption {
	return func(p Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantAuthorizationCode)
		return nil
	}
}

// WithImplicitGrant allows the implicit grant type and the associated
// response types.
func WithImplicitGrant() ProviderOption {
	return func(p Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantImplicit)
		return nil
	}
}

// WithScopes defines the scopes accepted by the provider.
// The scope openid is required, so it will be added in case scopes doesn't
// contain it.
func WithScopes(scopes ...goidc.Scope) ProviderOption {
	return func(p Provider) error {
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
	return func(p Provider) error {
		p.config.PARIsEnabled = true
		p.config.PARLifetimeSecs = lifetimeSecs
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
// For more info, see [WithPAR].
func WithPARRequired(lifetimeSecs int) ProviderOption {
	return func(p Provider) error {
		p.config.PARIsRequired = true
		return WithPAR(lifetimeSecs)(p)
	}
}

// WithUnregisteredRedirectURIsForPAR allows clients to inform unregistered
// redirect URIs during requests to pushed authorization endpoint.
// To enable pushed authorization request, see [WithPAR].
func WithUnregisteredRedirectURIsForPAR() ProviderOption {
	return func(p Provider) error {
		p.config.PARAllowUnregisteredRedirectURI = true
		return nil
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
// Clients can choose the signing algorithm by setting the attribute
// "request_object_signing_alg".
// By default, the max difference between "iat" and "exp" of request objects is
// set to [defaultJWTLifetimeSecs].
func WithJAR(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
		p.config.JARIsEnabled = true
		p.config.JARSigAlgs = algs
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
// For more info, see [WithJAR].
func WithJARRequired(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	return func(p Provider) error {
		p.config.JARIsRequired = true
		return WithJAR(alg, algs...)(p)
	}
}

func WithJARByReference(requireReqURIRegistration bool) ProviderOption {
	return func(p Provider) error {
		p.config.JARByReferenceIsEnabled = true
		p.config.JARRequestURIRegistrationIsRequired = requireReqURIRegistration
		return nil
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
// To enable JAR, see [WithJAR].
func WithJAREncryption(
	alg goidc.KeyEncryptionAlgorithm,
	algs ...goidc.KeyEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
		p.config.JAREncIsEnabled = true
		p.config.JARKeyEncAlgs = algs
		return nil
	}
}

// WithJARContentEncryptionAlgs overrides the default content encryption
// algorithm for request objects which is A128CBC-HS256.
// To enable JAR encryption, see [WithJAREncryption].
func WithJARContentEncryptionAlgs(
	alg goidc.ContentEncryptionAlgorithm,
	algs ...goidc.ContentEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
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
	defaultAlg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for JARM")
		}
		p.config.JARMIsEnabled = true
		p.config.JARMDefaultSigAlg = defaultAlg
		p.config.JARMSigAlgs = algs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted
// JWTs.
// The default content encryption algorithm is A128CBC-HS256.
// Clients can choose the encryption algorithms by setting the attributes
// "authorization_encrypted_response_al" and "authorization_encrypted_response_enc".
// To enabled JARM, see [WithJARM].
func WithJARMEncryption(
	alg goidc.KeyEncryptionAlgorithm,
	algs ...goidc.KeyEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
		p.config.JARMEncIsEnabled = true
		p.config.JARMKeyEncAlgs = algs
		return nil
	}
}

// WithJARMContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enabled JARM encryption, see [WithJARM].
func WithJARMContentEncryptionAlgs(
	defaultAlg goidc.ContentEncryptionAlgorithm,
	algs ...goidc.ContentEncryptionAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p Provider) error {
		p.config.JARMDefaultContentEncAlg = defaultAlg
		p.config.JARMContentEncAlgs = algs
		return nil
	}
}

// WithPrivateKeyJWTSignatureAlgs sets the signature algorithms for private key JWT
// authentication.
func WithPrivateKeyJWTSignatureAlgs(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)

	return func(p Provider) error {

		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for private_key_jwt")
		}

		for _, a := range algs {
			if strings.HasPrefix(string(a), "HS") {
				return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
			}
		}

		p.config.PrivateKeyJWTSigAlgs = algs
		return nil
	}
}

// WithSecretJWTSignatureAlgs sets the signature algorithms for private key JWT
// authentication.
func WithSecretJWTSignatureAlgs(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {

		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for client_secret_jwt")
		}

		for _, a := range alg {
			if !strings.HasPrefix(string(a), "HS") {
				return errors.New("asymmetric algorithms are not allowed for client_secret_jwt authentication")
			}
		}

		p.config.ClientSecretJWTSigAlgs = algs
		return nil
	}
}

// WithJWTLifetime defines a maximum threshold for lifetime of JWTs.
func WithJWTLifetime(secs int) ProviderOption {
	return func(p Provider) error {
		p.config.JWTLifetimeSecs = secs
		return nil
	}
}

// WithJWTLeewayTime defines a tolarance in seconds when validating time based
// claims in JWTs.
func WithJWTLeewayTime(secs int) ProviderOption {
	return func(p Provider) error {
		p.config.JWTLeewayTimeSecs = secs
		return nil
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() ProviderOption {
	return func(p Provider) error {
		p.config.IssuerRespParamIsEnabled = true
		return nil
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() ProviderOption {
	return func(p Provider) error {
		p.config.ClaimsParamIsEnabled = true
		return nil
	}
}

// WithAuthorizationDetails allows clients to make rich authorization requests.
func WithAuthorizationDetails(
	compareDetailsFunc goidc.CompareAuthDetailsFunc,
	authType string,
	authTypes ...string,
) ProviderOption {
	authTypes = appendIfNotIn(authTypes, authType)
	return func(p Provider) error {
		p.config.AuthDetailsIsEnabled = true
		p.config.CompareAuthDetailsFunc = compareDetailsFunc
		p.config.AuthDetailTypes = authTypes
		return nil
	}
}

// WithMTLS allows requests to be established with mutual TLS.
// The default logic to extract the client certificate is using the header
// [goidc.HeaderClientCert]. For more info, see [defaultClientCertFunc].
// The client certificate logic can be overridden with [WithClientCertFunc].
func WithMTLS(
	host string,
	clientCertFunc goidc.ClientCertFunc,
) ProviderOption {
	return func(p Provider) error {
		p.config.MTLSIsEnabled = true
		p.config.MTLSHost = host
		p.config.ClientCertFunc = clientCertFunc
		return nil
	}
}

// WithTLSCertTokenBinding makes requests to /token return tokens bound to the
// client certificate if any is sent.
// To enable MTLS, see [WithMTLS].
func WithTLSCertTokenBinding() ProviderOption {
	return func(p Provider) error {
		p.config.MTLSTokenBindingIsEnabled = true
		return nil
	}
}

// WithTLSCertTokenBindingRequired makes requests to /token return tokens bound to the
// client certificate.
// For more info, see [WithTLSCertTokenBinding].
func WithTLSCertTokenBindingRequired() ProviderOption {
	return func(p Provider) error {
		p.config.MTLSTokenBindingIsRequired = true
		return WithTLSCertTokenBinding()(p)
	}
}

// WithDPoP enables proof of possession with DPoP.
// It requires tokens to be bound to a cryptographic key generated by the client.
// By default, the max difference between the claims "iat" and "exp" of DPoP
// JWTs is set to [defaultJWTLifetimeSecs]
func WithDPoP(
	alg goidc.SignatureAlgorithm,
	algs ...goidc.SignatureAlgorithm,
) ProviderOption {
	algs = appendIfNotIn(algs, alg)
	return func(p Provider) error {
		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for DPoP")
		}
		p.config.DPoPIsEnabled = true
		p.config.DPoPSigAlgs = algs
		return nil
	}
}

// WithDPoPRequired makes DPoP required.
// For more information, see [WithDPoP].
func WithDPoPRequired(
	sigAlg goidc.SignatureAlgorithm,
	sigAlgs ...goidc.SignatureAlgorithm,
) ProviderOption {
	return func(p Provider) error {
		p.config.DPoPIsRequired = true
		return WithDPoP(sigAlg, sigAlgs...)(p)
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required in order to issue an access token to a client.
// For more info, see [WithTLSCertTokenBinding] and [WithDPoP].
func WithTokenBindingRequired() ProviderOption {
	return func(p Provider) error {
		p.config.TokenBindingIsRequired = true
		return nil
	}
}

func WithTokenAuthnMethods(
	method goidc.ClientAuthnType,
	methods ...goidc.ClientAuthnType,
) ProviderOption {
	methods = appendIfNotIn(methods, method)
	return func(p Provider) error {
		p.config.TokenAuthnMethods = methods
		return nil
	}
}

// WithTokenIntrospection allows authorized clients to introspect tokens.
func WithTokenIntrospection(
	f goidc.IsClientAllowedTokenInstrospectionFunc,
	method goidc.ClientAuthnType,
	methods ...goidc.ClientAuthnType,
) ProviderOption {
	methods = appendIfNotIn(methods, method)
	return func(p Provider) error {
		p.config.TokenIntrospectionIsEnabled = true
		p.config.IsClientAllowedTokenIntrospectionFunc = f
		p.config.TokenIntrospectionAuthnMethods = methods
		return nil
	}
}

// WithTokenRevocation allows clients to revoke tokens.
// If no authentication methods are specified, default to using the values set
// for the token endpoint.
func WithTokenRevocation(
	f goidc.IsClientAllowedFunc,
	method goidc.ClientAuthnType,
	methods ...goidc.ClientAuthnType,
) ProviderOption {
	methods = appendIfNotIn(methods, method)
	return func(p Provider) error {
		p.config.TokenRevocationIsEnabled = true
		p.config.IsClientAllowedTokenRevocationFunc = f
		p.config.TokenRevocationAuthnMethods = methods
		return nil
	}
}

// WithPKCE makes proof key for code exchange available to clients.
// The first code challenged informed is used as the default.
func WithPKCE(
	defaultMethod goidc.CodeChallengeMethod,
	methods ...goidc.CodeChallengeMethod,
) ProviderOption {
	methods = appendIfNotIn(methods, defaultMethod)
	return func(p Provider) error {
		p.config.PKCEIsEnabled = true
		p.config.PKCEDefaultChallengeMethod = defaultMethod
		p.config.PKCEChallengeMethods = methods
		return nil
	}
}

// WithPKCERequired makes proof key for code exchange required.
// For more info, see [WithPKCE].
func WithPKCERequired(
	method goidc.CodeChallengeMethod,
	methods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p Provider) error {
		p.config.PKCEIsRequired = true
		return WithPKCE(method, methods...)(p)
	}
}

// WithACRs makes available authentication context references.
// These values will be published as are in the well know endpoint response.
func WithACRs(
	value goidc.ACR,
	values ...goidc.ACR,
) ProviderOption {
	values = appendIfNotIn(values, value)
	return func(p Provider) error {
		p.config.ACRs = values
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the
// authorization endpoint.
// These values will be published as are in the well known endpoint response.
func WithDisplayValues(
	value goidc.DisplayValue,
	values ...goidc.DisplayValue,
) ProviderOption {
	values = appendIfNotIn(values, value)
	return func(p Provider) error {
		p.config.DisplayValues = values
		return nil
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
// This defines how long an authorization request may last.
// The default is [defaultAuthnSessionTimeoutSecs].
func WithAuthenticationSessionTimeout(secs int) ProviderOption {
	return func(p Provider) error {
		p.config.AuthnSessionTimeoutSecs = secs
		return nil
	}
}

// WithStaticClient adds a static client to the provider.
// The static clients are kept in memory only and are checked before consulting
// the client manager.
func WithStaticClient(client *goidc.Client) ProviderOption {
	return func(p Provider) error {
		p.config.StaticClients = append(p.config.StaticClients, client)
		return nil
	}
}

// WithPolicy adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func WithPolicy(policy goidc.AuthnPolicy) ProviderOption {
	return func(p Provider) error {
		p.config.Policies = append(p.config.Policies, policy)
		return nil
	}
}

// WithAuthorizeErrorPlugin defines a handler to be executed when the
// authorization request results in error, but the error can't be redirected.
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithRenderErrorFunc(render goidc.RenderErrorFunc) ProviderOption {
	return func(p Provider) error {
		p.config.RenderErrorFunc = render
		return nil
	}
}

// WithNotifyErrorFunc defines a handler to be executed when an error happens.
// For instance, this can be used to log information about the error.
func WithNotifyErrorFunc(f goidc.NotifyErrorFunc) ProviderOption {
	return func(p Provider) error {
		p.config.NotifyErrorFunc = f
		return nil
	}
}

// WithCheckJTIFunc registers a function to validate JWT IDs (JTI) during JWT
// processing.
// This function is used to prevent replay attacks by ensuring that each JTI is
// unique and not reused.
func WithCheckJTIFunc(f goidc.CheckJTIFunc) ProviderOption {
	return func(p Provider) error {
		p.config.CheckJTIFunc = f
		return nil
	}
}

// WithResourceIndicators enables client to indicate which resources they intend
// to access.
func WithResourceIndicators(
	resource string,
	resources ...string,
) ProviderOption {
	resources = appendIfNotIn(resources, resource)
	return func(p Provider) error {
		p.config.ResourceIndicatorsIsEnabled = true
		p.config.Resources = resources
		return nil
	}
}

// WithResourceIndicatorsRequired makes resource indicators required.
// For more info, see [WithResourceIndicators].
func WithResourceIndicatorsRequired(
	resource string,
	resources ...string,
) ProviderOption {
	return func(p Provider) error {
		p.config.ResourceIndicatorsIsRequired = true
		return WithResourceIndicators(resource, resources...)(p)
	}
}

// WithHTTPClientFunc defines how to generate the client used to make HTTP
// requests to, for instance, a client's JWKS endpoint.
// The default behavior is to use the default HTTP client from the std library.
func WithHTTPClientFunc(f goidc.HTTPClientFunc) ProviderOption {
	return func(p Provider) error {
		p.config.HTTPClientFunc = f
		return nil
	}
}

// WithJWTBearerGrant enables the JWT bearer grant type.
func WithJWTBearerGrant(
	f goidc.HandleJWTBearerGrantAssertionFunc,
) ProviderOption {
	return func(p Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes,
			goidc.GrantJWTBearer)
		p.config.HandleJWTBearerGrantAssertionFunc = f
		return nil
	}
}

// WithJWTBearerGrantClientAuthnRequired makes client authentication required
// for the jwt bearer grant type.
func WithJWTBearerGrantClientAuthnRequired() ProviderOption {
	return func(p Provider) error {
		p.config.JWTBearerGrantClientAuthnIsRequired = true
		return nil
	}
}

// WithSubIdentifierTypes sets de subject identifier types available for clients.
//
// If [goidc.SubIdentifierPairwise] is informed, the default behavior for
// generating pairwise subjects is to keep the value as is.
// This can be overriden with [WithGeneratePairwiseSubIDFunc].
// Also, only opaque tokens are issued when pairwise IDs are applied to avoid
// information leakage.
func WithSubIdentifierTypes(
	defaultIDType goidc.SubIdentifierType,
	idTypes ...goidc.SubIdentifierType,
) ProviderOption {
	idTypes = appendIfNotIn(idTypes, defaultIDType)
	return func(p Provider) error {
		p.config.DefaultSubIdentifierType = defaultIDType
		p.config.SubIdentifierTypes = idTypes
		return nil
	}
}

func WithGeneratePairwiseSubIDFunc(
	f goidc.GeneratePairwiseSubIDFunc,
) ProviderOption {
	return func(p Provider) error {
		p.config.GeneratePairwiseSubIDFunc = f
		return nil
	}
}

func WithSignFunc(f goidc.SignerFunc) ProviderOption {
	return func(p Provider) error {
		p.config.SignerFunc = f
		return nil
	}
}

func WithDecryptFunc(f goidc.DecrypterFunc) ProviderOption {
	return func(p Provider) error {
		p.config.DecrypterFunc = f
		return nil
	}
}

func WithErrorURI(uri string) ProviderOption {
	return func(p Provider) error {
		p.config.ErrorURI = uri
		return nil
	}
}

// appendIfNotIn adds 'value' to the beginning of 'values' if it is not already
// present.
func appendIfNotIn[T comparable](values []T, value T) []T {
	if !slices.Contains(values, value) {
		return append([]T{value}, values...) // Prepend value if not found
	}
	return values
}
