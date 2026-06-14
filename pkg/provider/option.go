package provider

import (
	"errors"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Option func(p *Provider) error

// WithProfile adjusts the server's behavior for non-configurable settings,
// ensuring compliance with the associated specification. Depending on
// the profile selected, the server may modify its operations to meet specific
// requirements dictated by the corresponding standards or protocols.
func WithProfile(profile goidc.Profile) Option {
	return func(p *Provider) error {
		p.config.Profile = profile
		return nil
	}
}

func WithProfileValidation() Option {
	return func(p *Provider) error {
		p.profileValidationIsEnabled = true
		return nil
	}
}

// WithAuthCodeGrant enables the authorization endpoint flows backed by
// authentication sessions.
//
// It always enables the `authorization_code` grant type and registers the
// response types accepted at the authorization endpoint.
//
// The response types determine which flows are available:
//   - `code` enables the authorization code flow
//   - `token` and `id_token` enable implicit flows
//   - combined response types such as `code id_token` enable hybrid flows
//
// If any implicit or hybrid response type is informed, the provider also adds
// the implicit grant type internally.
//
// If manager is nil, the default in-memory storage is used.
func WithAuthCodeGrant(manager goidc.AuthManager, rts ...goidc.ResponseType) Option {
	return func(p *Provider) error {
		p.config.AuthManager = manager
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantAuthorizationCode)
		p.config.ResponseTypes = append(p.config.ResponseTypes, rts...)
		return nil
	}
}

func WithGrantIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.GrantIDFunc = f
		return nil
	}
}

func WithPARIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.PARIDFunc = f
		return nil
	}
}

func WithCIBAIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.CIBAIDFunc = f
		return nil
	}
}

func WithOpaqueTokenFunc(f goidc.OpaqueTokenFunc) Option {
	return func(p *Provider) error {
		p.config.OpaqueTokenFunc = f
		return nil
	}
}

// WithOpaqueTokens enables opaque access token storage and retrieval.
// If manager is nil, the default in-memory storage is used.
func WithOpaqueTokens(manager goidc.OpaqueTokenManager) Option {
	return func(p *Provider) error {
		p.config.OpaqueTokenIsEnabled = true
		p.config.OpaqueTokenManager = manager
		return nil
	}
}

// WithPathPrefix defines a shared prefix for all endpoints.
// When using the provider http handler directly, the path prefix must be added
// to the router.
//
//	op, err := provider.New(
//		"http://example.com",
//		nil,
//		jwksFunc,
//		provider.WithPathPrefix("/auth"),
//	)
//	server := http.NewServeMux()
//	server.Handle("/auth/", op.Handler())
func WithPathPrefix(prefix string) Option {
	return func(p *Provider) error {
		p.config.EndpointPrefix = prefix
		return nil
	}
}

// WithJWKSEndpoint overrides the default value for the jwks endpoint which is
// [defaultEndpointJSONWebKeySet].
func WithJWKSEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.JWKSEndpoint = endpoint
		return nil
	}
}

// WithTokenEndpoint overrides the default value for the token
// endpoint which is [defaultEndpointToken].
func WithTokenEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.TokenEndpoint = endpoint
		return nil
	}
}

// WithAuthorizeEndpoint overrides the default value for the authorization endpoint
// which is [defaultEndpointAuthorize].
func WithAuthorizeEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.AuthorizationEndpoint = endpoint
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is [defaultEndpointPushedAuthorizationRequest].
// To enable pushed authorization request, see [WithPAR].
func WithPAREndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.PAREndpoint = endpoint
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is [defaultEndpointDynamicClient].
// To enable dynamic client registration, see [WithDCR].
func WithDCREndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.DCREndpoint = endpoint
		return nil
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is [defaultEndpointUserInfo].
func WithUserInfoEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.UserInfoEndpoint = endpoint
		return nil
	}
}

// WithTokenIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is [defaultEndpointTokenIntrospection]
// To enable token introspection, see [WithTokenIntrospection].
func WithTokenIntrospectionEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.TokenIntrospectionEndpoint = endpoint
		return nil
	}
}

// WithTokenRevocationEndpoint overrides the default value for the token
// revocation endpoint which is [defaultEndpointTokenRevocation]
// To enable token revocation, see [WithTokenRevocation].
func WithTokenRevocationEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.TokenRevocationEndpoint = endpoint
		return nil
	}
}

// WithClaims signals support for user claims.
// The claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared in the field "claims_supported" of the
// openid configuration endpoint response.
// The default value for "claim_types_supported" is set to "normal".
// To define other claim types, see [WithClaimTypes].
func WithClaims(claim string, claims ...string) Option {
	claims = appendIfNotIn(claims, claim)
	return func(p *Provider) error {
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
		return nil
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The values provided are published at "claim_types_supported".
// To add support for claims, see [WithClaims].
func WithClaimTypes(claimType goidc.ClaimType, claimTypes ...goidc.ClaimType) Option {
	claimTypes = appendIfNotIn(claimTypes, claimType)
	return func(p *Provider) error {
		p.config.ClaimTypes = claimTypes
		return nil
	}
}

// WithUserInfoSignatureAlgs set the algorithms available to sign the user info
// endpoint response.
func WithUserInfoSignatureAlgs(defaultAlg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
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
func WithUserInfoEncryption(keyEncAlg goidc.KeyEncryptionAlgorithm, keyEncAlgs ...goidc.KeyEncryptionAlgorithm) Option {
	keyEncAlgs = appendIfNotIn(keyEncAlgs, keyEncAlg)
	return func(p *Provider) error {
		p.config.UserInfoEncIsEnabled = true
		p.config.UserInfoKeyEncAlgs = keyEncAlgs
		return nil
	}
}

// WithUserInfoContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enable encryption of user information, see [WithUserInfoEncryption].
func WithUserInfoContentEncryptionAlgs(defaultAlg goidc.ContentEncryptionAlgorithm, algs ...goidc.ContentEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		p.config.UserInfoDefaultContentEncAlg = defaultAlg
		p.config.UserInfoContentEncAlgs = algs
		return nil
	}
}

// WithIDTokenSignatureAlgs sets the algorithms available to sign ID tokens.
func WithIDTokenSignatureAlgs(defaultAlg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		p.config.IDTokenDefaultSigAlg = defaultAlg
		p.config.IDTokenSigAlgs = algs
		return nil
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// It defines how long ID tokens will be valid for when issuing them.
// The default is [defaultIDTokenLifetimeSecs].
func WithIDTokenLifetime(secs int) Option {
	return func(p *Provider) error {
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
func WithIDTokenEncryption(alg goidc.KeyEncryptionAlgorithm, algs ...goidc.KeyEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		p.config.IDTokenEncIsEnabled = true
		p.config.IDTokenKeyEncAlgs = algs
		return nil
	}
}

// WithIDTokenContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enable encryption of ID tokens, see [WithIDTokenEncryption].
func WithIDTokenContentEncryptionAlgs(defaultAlg goidc.ContentEncryptionAlgorithm, algs ...goidc.ContentEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		p.config.IDTokenDefaultContentEncAlg = defaultAlg
		p.config.IDTokenContentEncAlgs = algs
		return nil
	}
}

// WithDCR allows clients to be registered dynamically.
// If manager is nil, the default in-memory storage is used.
//
// By default, enabling DCR does not require an initial access token, so any
// caller that can reach the endpoint can create clients. Production
// deployments should typically combine this option with
// [WithDCRInitialTokenValidator] and/or [WithDCRClientHandler] to enforce
// their registration policy.
//
// To make registration access tokens rotate, see [WithDCRTokenRotation].
func WithDCR(manager goidc.DCRManager) Option {
	return func(p *Provider) error {
		p.config.DCRIsEnabled = true
		p.config.DCRManager = manager
		return nil
	}
}

// WithRPMetadataChoices enables support for the RP Metadata Choices extension,
// allowing clients to advertise priority lists for algorithm and method preferences
// during registration. The server selects the best supported value from each list.
//
// See https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html.
func WithRPMetadataChoices() Option {
	return func(p *Provider) error {
		p.config.RPMetadataChoicesIsEnabled = true
		return nil
	}
}

// WithDCRClientHandler installs custom logic for DCR and DCM requests.
//
// Use it to enforce registration rules, validate metadata, reject unwanted
// clients, or apply default values during create and update requests.
func WithDCRClientHandler(f goidc.DCRHandleClientFunc) Option {
	return func(p *Provider) error {
		p.config.DCRHandleClientFunc = f
		return nil
	}
}

// WithDCRInitialTokenValidator validates the initial access token used when
// creating clients through DCR.
//
// Without this option, client creation is open to any caller that can reach the
// registration endpoint.
func WithDCRInitialTokenValidator(f goidc.DCRValidateInitialTokenFunc) Option {
	return func(p *Provider) error {
		p.config.DCRValidateInitialTokenFunc = f
		return nil
	}
}

// WithDCRRegistrationTokenFunc customizes the registration access token issued
// for DCR and DCM operations.
func WithDCRRegistrationTokenFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.DCRRegistrationTokenFunc = f
		return nil
	}
}

func WithLocalhostRedirectURIs() Option {
	return func(p *Provider) error {
		p.config.LocalhostRedirectURIIsEnabled = true
		return nil
	}
}

func WithDCRClientID(f goidc.ClientIDFunc) Option {
	return func(p *Provider) error {
		p.config.DCRClientIDFunc = f
		return nil
	}
}

// WithDCRTokenRotation makes the registration access token rotate during client
// read and update requests.
// To enable dynamic client registration, see [WithDCR].
func WithDCRTokenRotation() Option {
	return func(p *Provider) error {
		p.config.DCRTokenRotationIsEnabled = true
		return nil
	}
}

// WithDCRSecretRotation makes client secrets rotate during client read and
// update requests when the client uses a secret-based authentication method.
// To enable dynamic client registration, see [WithDCR].
func WithDCRSecretRotation() Option {
	return func(p *Provider) error {
		p.config.DCRSecretRotationIsEnabled = true
		return nil
	}
}

// WithDCRSecretLifetime sets the client secret lifetime in seconds for
// dynamically registered clients that use a secret-based authentication method.
// A value of 0 means the issued client secret does not expire.
// To enable dynamic client registration, see [WithDCR].
func WithDCRSecretLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.DCRSecretLifetimeSecs = secs
		return nil
	}
}

func WithRefreshTokenShouldIssue(f goidc.RefreshTokenShouldIssueFunc) Option {
	return func(p *Provider) error {
		p.config.RefreshTokenShouldIssueFunc = f
		return nil
	}
}

func WithRefreshTokenFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.RefreshTokenFunc = f
		return nil
	}
}

func WithDeviceCodeFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.DeviceCodeFunc = f
		return nil
	}
}

// WithRefreshTokenLifetime sets the refresh token lifetime in seconds.
// A value of 0 means issued refresh tokens do not expire.
func WithRefreshTokenLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.RefreshTokenLifetimeSecs = secs
		return nil
	}
}

// WithRefreshTokenRotation causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
// To enable the refresh token grant, see [WithRefreshTokenGrant].
func WithRefreshTokenRotation() Option {
	return func(p *Provider) error {
		p.config.RefreshTokenRotationIsEnabled = true
		return nil
	}
}

// WithCIBAGrant enables the CIBA grant type and configures the delivery modes
// clients are allowed to use.
//
// The manager is used to persist pending CIBA sessions and grants resolved from
// them. If manager is nil, the default in-memory storage is used.
func WithCIBAGrant(manager goidc.CIBAManager, mode goidc.CIBATokenDeliveryMode, modes ...goidc.CIBATokenDeliveryMode) Option {
	modes = appendIfNotIn(modes, mode)
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantCIBA)
		p.config.CIBAManager = manager
		p.config.CIBATokenDeliveryModes = modes
		return nil
	}
}

func WithCIBAProfile(profile goidc.CIBAProfile) Option {
	return func(p *Provider) error {
		p.config.CIBAProfile = profile
		return nil
	}
}

// WithCIBAEndpoint overrides the default value for the CIBA endpoint which is [defaultEndpointCIBA].
func WithCIBAEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.CIBAEndpoint = endpoint
		return nil
	}
}

func WithCIBASessionHandler(f goidc.HandleSessionFunc) Option {
	return func(p *Provider) error {
		p.config.CIBAHandleSessionFunc = f
		return nil
	}
}

// WithCIBAHTTPClientFunc sets a custom HTTP client function for outbound CIBA
// client notifications in ping and push delivery modes. When unset, the
// provider falls back to [WithHTTPClientFunc].
func WithCIBAHTTPClientFunc(f goidc.HTTPClientFunc) Option {
	return func(p *Provider) error {
		p.config.CIBAHTTPClientFunc = f
		return nil
	}
}

func WithCIBAJAR(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		p.config.CIBAJARIsEnabled = true
		p.config.CIBAJARSigAlgs = algs
		return nil
	}
}

func WithCIBAJARRequired(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		p.config.CIBAJARIsRequired = true
		return WithCIBAJAR(alg, algs...)(p)
	}
}

func WithCIBAUserCode() Option {
	return func(p *Provider) error {
		p.config.CIBAUserCodeIsEnabled = true
		return nil
	}
}

func WithCIBAPollingInterval(interval int) Option {
	return func(p *Provider) error {
		p.config.CIBAPollingIntervalSecs = interval
		return nil
	}
}

func WithCIBALifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.CIBADefaultSessionLifetimeSecs = secs
		return nil
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all
// the authorization requests.
func WithOpenIDScopeRequired() Option {
	return func(p *Provider) error {
		p.config.OpenIDIsRequired = true
		return nil
	}
}

// WithTokenOptions configures how access tokens are issued by the provider.
//
// It is called for each issuance and can choose, for example, the token format
// (opaque or JWT) and token lifetime based on the grant and client.
//
// If pairwise subject identifiers are enabled and applicable to the subject,
// the token will be issued as an opaque token even when the token option is set
// to issue a JWT token. Opaque tokens require [WithOpaqueTokens] to be enabled.
func WithTokenOptions(tokenOpts goidc.TokenOptionsFunc) Option {
	return func(p *Provider) error {
		p.config.TokenOptionsFunc = tokenOpts
		return nil
	}
}

// WithGrantHandler defines a function executed every time a new grant is created.
// It can be used to perform validations or change the grant information before
// issuing a new access token.
func WithGrantHandler(f goidc.HandleGrantFunc) Option {
	return func(p *Provider) error {
		p.config.HandleGrantFunc = f
		return nil
	}
}

// WithTokenHandler defines a function executed every time a new token is created.
// It can be used to perform validations or change the token information before
// issuing it.
func WithTokenHandler(f goidc.HandleTokenFunc) Option {
	return func(p *Provider) error {
		p.config.HandleTokenFunc = f
		return nil
	}
}

// WithIDTokenClaims defines a function that returns additional claims to include
// in ID tokens. It is called at ID token issuance time.
func WithIDTokenClaims(f goidc.IDTokenClaimsFunc) Option {
	return func(p *Provider) error {
		p.config.IDTokenClaimsFunc = f
		return nil
	}
}

// WithUserInfoClaims defines a function that returns additional claims to include
// in the userinfo response. It is called when the userinfo endpoint is requested.
func WithUserInfoClaims(f goidc.UserInfoClaimsFunc) Option {
	return func(p *Provider) error {
		p.config.UserInfoClaimsFunc = f
		return nil
	}
}

// WithTokenClaims defines a function that returns additional claims to include
// in JWT access tokens. It is called at access token issuance time.
func WithTokenClaims(f goidc.TokenClaimsFunc) Option {
	return func(p *Provider) error {
		p.config.TokenClaimsFunc = f
		return nil
	}
}

// WithRefreshTokenGrant enables the `refresh_token` grant type.
//
// Refresh token requests do not create a new authorization. Instead, they load
// an existing grant by its refresh token and issue a new access token under the
// same grant.
//
// The manager is used to resolve grants by refresh token. If manager is nil,
// the default in-memory storage is used.
func WithRefreshTokenGrant(manager goidc.RefreshTokenManager) Option {
	return func(p *Provider) error {
		p.config.RefreshTokenManager = manager
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		return nil
	}
}

// WithClientCredentialsGrant enables the `client_credentials` grant type.
//
// This flow does not involve an end-user or an authentication session. The
// client authenticates directly at the token endpoint and receives a token for
// itself.
func WithClientCredentialsGrant() Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantClientCredentials)
		return nil
	}
}

// WithJWTBearerGrant enables the `urn:ietf:params:oauth:grant-type:jwt-bearer`
// grant type.
//
// The handler receives the raw assertion from the token request and must
// validate it according to the deployment rules. If the assertion is accepted,
// it returns the subject represented by that assertion so the provider can
// create a grant and issue a token from it.
//
// To also require client authentication on JWT bearer token requests, see
// [WithJWTBearerGrantClientAuthnRequired].
func WithJWTBearerGrant(f goidc.JWTBearerHandleAssertionFunc) Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantJWTBearer)
		p.config.JWTBearerHandleAssertionFunc = f
		return nil
	}
}

// WithTokenExchangeGrant enables the token exchange grant type (RFC 8693).
//
// The handler receives the token exchange request parameters and must validate
// the subject and actor tokens according to the deployment rules. It returns
// the subject to use for the resulting grant.
//
// To also require client authentication on token exchange requests, see
// [WithTokenExchangeClientAuthnRequired].
func WithTokenExchangeGrant(f goidc.TokenExchangeHandleFunc) Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantTokenExchange)
		p.config.TokenExchangeHandleFunc = f
		return nil
	}
}

// WithTokenExchangeClientAuthnRequired makes client authentication
// required for the token exchange grant type.
func WithTokenExchangeClientAuthnRequired() Option {
	return func(p *Provider) error {
		p.config.TokenExchangeClientAuthnIsRequired = true
		return nil
	}
}

func WithPreAuthorizedCodeGrant() Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantPreAuthorizedCode)
		return nil
	}
}

// WithDeviceGrant enables the device authorization grant.
// If manager is nil, the default in-memory storage is used.
func WithDeviceGrant(manager goidc.DeviceAuthManager, promptFunc goidc.RenderFunc, confirmationFunc goidc.RenderFunc) Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantDeviceCode)
		p.config.DeviceAuthManager = manager
		p.config.DeviceAuthPromptUserCodeFunc = promptFunc
		p.config.DeviceAuthRenderConfirmationFunc = confirmationFunc
		return nil
	}
}

// WithScopes defines the scopes accepted by the provider.
// The scope openid is required, so it will be added in case the scope list doesn't
// contain it.
func WithScopes(scopes ...goidc.Scope) Option {
	return func(p *Provider) error {
		p.config.Scopes = scopes
		// The scope openid is required to be among the scopes.
		for _, scope := range p.config.Scopes {
			if scope.ID == goidc.ScopeOpenID.ID {
				return nil
			}
		}
		p.config.Scopes = append(p.config.Scopes, goidc.ScopeOpenID)
		return nil
	}
}

// WithPAR allows authorization flows to start at the pushed authorization
// request endpoint.
//
// The manager stores the pushed authorization request session that will later
// be resolved by `request_uri` at the authorization endpoint. If manager is
// nil, the default in-memory storage is used.
func WithPAR(manager goidc.PARManager) Option {
	return func(p *Provider) error {
		p.config.PARIsEnabled = true
		p.config.PARManager = manager
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
// If manager is nil, the default in-memory storage is used.
// For more info, see [WithPAR].
func WithPARRequired(manager goidc.PARManager) Option {
	return func(p *Provider) error {
		p.config.PARIsRequired = true
		return WithPAR(manager)(p)
	}
}

func WithPARSessionHandler(f goidc.HandleSessionFunc) Option {
	return func(p *Provider) error {
		p.config.PARHandleSessionFunc = f
		return nil
	}
}

func WithPARLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.PARLifetimeSecs = secs
		return nil
	}
}

// WithPARUnregisteredRedirectURIs allows clients to inform unregistered
// redirect URIs during requests to pushed authorization endpoint.
// To enable pushed authorization request, see [WithPAR].
func WithPARUnregisteredRedirectURIs() Option {
	return func(p *Provider) error {
		p.config.PARUnregisteredRedirectURIIsEnabled = true
		return nil
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
// Clients can choose the signing algorithm by setting the attribute
// "request_object_signing_alg".
// By default, the max difference between "iat" and "exp" of request objects is
// set to [defaultJWTLifetimeSecs].
func WithJAR(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		p.config.JARIsEnabled = true
		p.config.JARSigAlgs = algs
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
// For more info, see [WithJAR].
func WithJARRequired(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		p.config.JARIsRequired = true
		return WithJAR(alg, algs...)(p)
	}
}

// WithJARByReference enables support for request objects referenced by the
// "request_uri" authorization parameter.
func WithJARByReference() Option {
	return func(p *Provider) error {
		p.config.JARByReferenceIsEnabled = true
		return nil
	}
}

// WithJARByReferenceUnregisteredURIs allows request_uri values that were not
// pre-registered by the client.
// Avoid using this option when possible, as it expands the attack surface for
// server-side request_uri fetches.
// To enable request objects by reference, see [WithJARByReference].
func WithJARByReferenceUnregisteredURIs() Option {
	return func(p *Provider) error {
		p.config.JARByReferenceUnregisteredURIIsEnabled = true
		return nil
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
// To enable JAR, see [WithJAR].
func WithJAREncryption(alg goidc.KeyEncryptionAlgorithm, algs ...goidc.KeyEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		p.config.JAREncIsEnabled = true
		p.config.JARKeyEncAlgs = algs
		return nil
	}
}

// WithJARContentEncryptionAlgs overrides the default content encryption
// algorithm for request objects which is A128CBC-HS256.
// To enable JAR encryption, see [WithJAREncryption].
func WithJARContentEncryptionAlgs(alg goidc.ContentEncryptionAlgorithm, algs ...goidc.ContentEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
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
func WithJARM(defaultAlg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for JARM")
		}
		p.config.JARMIsEnabled = true
		p.config.JARMSigAlgDefault = defaultAlg
		p.config.JARMSigAlgs = algs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted JWTs.
// The default content encryption algorithm is A128CBC-HS256.
// Clients can choose the encryption algorithms by setting the attributes
// "authorization_encrypted_response_alg" and "authorization_encrypted_response_enc".
// To enable JARM, see [WithJARM].
func WithJARMEncryption(alg goidc.KeyEncryptionAlgorithm, algs ...goidc.KeyEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		p.config.JARMEncIsEnabled = true
		p.config.JARMKeyEncAlgs = algs
		return nil
	}
}

// WithJARMContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// To enable JARM encryption, see [WithJARM].
func WithJARMContentEncryptionAlgs(defaultAlg goidc.ContentEncryptionAlgorithm, algs ...goidc.ContentEncryptionAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		p.config.JARMContentEncAlgDefault = defaultAlg
		p.config.JARMContentEncAlgs = algs
		return nil
	}
}

// WithJWTLifetime defines a maximum threshold for lifetime of JWTs.
func WithJWTLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.JWTLifetimeSecs = secs
		return nil
	}
}

// WithJWTLeewayTime defines a tolerance in seconds when validating time based
// claims in JWTs.
func WithJWTLeewayTime(secs int) Option {
	return func(p *Provider) error {
		p.config.JWTLeewayTimeSecs = secs
		return nil
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() Option {
	return func(p *Provider) error {
		p.config.IssuerRespParamIsEnabled = true
		return nil
	}
}

// WithFormPostResponseMode enables support for the `form_post` response mode
// at the authorization endpoint.
func WithFormPostResponseMode() Option {
	return func(p *Provider) error {
		p.config.ResponseModes = appendIfNotIn(p.config.ResponseModes, goidc.ResponseModeFormPost)
		return nil
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() Option {
	return func(p *Provider) error {
		p.config.ClaimsParamIsEnabled = true
		return nil
	}
}

// WithRAR enables Rich Authorization Requests (RFC 9396).
func WithRAR(typ goidc.AuthDetailType, types ...goidc.AuthDetailType) Option {
	types = appendIfNotIn(types, typ)
	return func(p *Provider) error {
		p.config.RARIsEnabled = true
		p.config.RARDetailTypes = types
		return nil
	}
}

func WithRARDetailValidator(f goidc.RARValidateDetailFunc) Option {
	return func(p *Provider) error {
		p.config.RARValidateDetailFunc = f
		return nil
	}
}

// WithRARDetailsComparator sets the function used to validate that the
// authorization details requested during authorization_code or refresh_token
// grants are consistent with the originally granted ones.
func WithRARDetailsComparator(f goidc.RARCompareDetailsFunc) Option {
	return func(p *Provider) error {
		p.config.RARCompareDetailsFunc = f
		return nil
	}
}

// WithMTLS allows requests to be established with mutual TLS.
func WithMTLS(host string, f goidc.ClientCertFunc) Option {
	return func(p *Provider) error {
		p.config.MTLSIsEnabled = true
		p.config.MTLSHost = host
		p.config.ClientCertFunc = f
		return nil
	}
}

// WithTLSTokenBinding makes requests to /token return tokens bound to the
// client certificate if any is sent.
// To enable MTLS, see [WithMTLS].
func WithTLSTokenBinding() Option {
	return func(p *Provider) error {
		p.config.MTLSTokenBindingIsEnabled = true
		return nil
	}
}

// WithTLSTokenBindingRequired makes requests to /token return tokens bound to the
// client certificate.
// For more info, see [WithTLSTokenBinding].
func WithTLSTokenBindingRequired() Option {
	return func(p *Provider) error {
		p.config.MTLSTokenBindingIsRequired = true
		return WithTLSTokenBinding()(p)
	}
}

// WithDPoP enables proof of possession with DPoP.
// It requires tokens to be bound to a cryptographic key generated by the client.
// By default, the max difference between the claims "iat" and "exp" of DPoP JWTs is set to [defaultJWTLifetimeSecs].
func WithDPoP(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
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
func WithDPoPRequired(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		p.config.DPoPIsRequired = true
		return WithDPoP(alg, algs...)(p)
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required in order to issue an access token to a client.
// For more info, see [WithTLSTokenBinding] and [WithDPoP].
func WithTokenBindingRequired() Option {
	return func(p *Provider) error {
		p.config.TokenBindingIsRequired = true
		return nil
	}
}

func WithDefaultAuthn(method goidc.AuthnMethod) Option {
	return func(p *Provider) error {
		p.config.AuthnMethodDefault = method
		return nil
	}
}

// WithNoneAuthn enables the "none" client authentication method.
func WithNoneAuthn() Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodNone)
		return nil
	}
}

// WithSecretPostAuthn enables the "client_secret_post" client
// authentication method.
func WithSecretPostAuthn() Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodSecretPost)
		return nil
	}
}

// WithSecretBasicAuthn enables the "client_secret_basic" client
// authentication method.
func WithSecretBasicAuthn() Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodSecretBasic)
		return nil
	}
}

// WithPrivateKeyJWTAuthn enables the "private_key_jwt" client
// authentication method with the given signature algorithms.
func WithPrivateKeyJWTAuthn(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for private_key_jwt")
		}
		for _, a := range algs {
			if strings.HasPrefix(string(a), "HS") {
				return errors.New("symmetric algorithms are not allowed for private_key_jwt authentication")
			}
		}
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT)
		p.config.AuthnMethodPrivateKeyJWTSigAlgs = algs
		return nil
	}
}

// WithSecretJWTAuthn enables the "client_secret_jwt" client
// authentication method with the given signature algorithms.
func WithSecretJWTAuthn(alg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, alg)
	return func(p *Provider) error {
		if slices.Contains(algs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for client_secret_jwt")
		}
		for _, a := range algs {
			if !strings.HasPrefix(string(a), "HS") {
				return errors.New("asymmetric algorithms are not allowed for client_secret_jwt authentication")
			}
		}
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodSecretJWT)
		p.config.AuthnMethodSecretJWTSigAlgs = algs
		return nil
	}
}

// WithTLSAuthn enables the "tls_client_auth" client authentication
// method.
func WithTLSAuthn() Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodTLS)
		return nil
	}
}

// WithSelfSignedTLSAuthn enables the "self_signed_tls_client_auth" client
// authentication method.
func WithSelfSignedTLSAuthn() Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodSelfSignedTLS)
		return nil
	}
}

// WithAttestationJWTAuthn enables the "attest_jwt_client_auth" client
// authentication method with the given trusted attestation issuers.
func WithAttestationJWTAuthn(issuer goidc.AttestationIssuer, issuers ...goidc.AttestationIssuer) Option {
	return func(p *Provider) error {
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodAttestationJWT)
		p.config.AuthnMethodAttestationJWTIssuers = append([]goidc.AttestationIssuer{issuer}, issuers...)
		return nil
	}
}

// WithTokenIntrospection enables the token introspection endpoint.
//
// The client calling the endpoint must authenticate first. For each
// introspection request, the provided function receives the authenticated
// client and the resolved token and must return whether that client is
// allowed to introspect it.
//
// If the function allows the request, the provider returns the introspection
// response. For JWT access tokens, the provider validates the token signature
// and resolves the grant via the grant_id claim. For opaque access tokens,
// the provider looks up the stored token record. If the token is unknown,
// expired, or otherwise inactive, the endpoint returns an inactive response.
func WithTokenIntrospection(f goidc.IsClientAllowedTokenIntrospectionFunc) Option {
	return func(p *Provider) error {
		p.config.TokenIntrospectionIsEnabled = true
		p.config.TokenIntrospectionIsClientAllowedFunc = f
		return nil
	}
}

// WithTokenRevocation allows clients to revoke tokens.
//
// Refresh token revocation always invalidates the underlying grant and related
// access tokens. For opaque access tokens, revocation revokes only the
// presented token unless [WithTokenRevocationRevokeGrantOnAccessToken] is also
// enabled. For JWT access tokens, revocation is only effective when
// [WithTokenRevocationRevokeGrantOnAccessToken] is enabled, since JWTs are not
// stored server-side.
func WithTokenRevocation(f goidc.IsClientAllowedFunc) Option {
	return func(p *Provider) error {
		p.config.TokenRevocationIsEnabled = true
		p.config.TokenRevocationIsClientAllowedFunc = f
		return nil
	}
}

// WithTokenRevocationRevokeGrantOnAccessToken makes access token revocation
// revoke the underlying grant instead of revoking only the presented access
// token. For JWT access tokens, this is required for revocation to have any
// effect, since JWTs are not stored server-side.
func WithTokenRevocationRevokeGrantOnAccessToken() Option {
	return func(p *Provider) error {
		p.config.TokenRevocationRevokeGrantOnAccessTokenIsEnabled = true
		return nil
	}
}

// WithPKCE makes proof key for code exchange available to clients.
// The first code challenged informed is used as the default.
func WithPKCE(defaultMethod goidc.CodeChallengeMethod, methods ...goidc.CodeChallengeMethod) Option {
	methods = appendIfNotIn(methods, defaultMethod)
	return func(p *Provider) error {
		p.config.PKCEIsEnabled = true
		p.config.PKCEDefaultChallengeMethod = defaultMethod
		p.config.PKCEChallengeMethods = methods
		return nil
	}
}

// WithPKCERequired makes proof key for code exchange required.
// For more info, see [WithPKCE].
func WithPKCERequired(method goidc.CodeChallengeMethod, methods ...goidc.CodeChallengeMethod) Option {
	return func(p *Provider) error {
		p.config.PKCEIsRequired = true
		return WithPKCE(method, methods...)(p)
	}
}

// WithACRs makes available authentication context references.
// These values will be published as are in the openid configuration endpoint response.
func WithACRs(value goidc.ACR, values ...goidc.ACR) Option {
	values = appendIfNotIn(values, value)
	return func(p *Provider) error {
		p.config.ACRs = values
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the
// authorization endpoint.
// These values will be published as are in the openid configuration endpoint response.
func WithDisplayValues(value goidc.DisplayValue, values ...goidc.DisplayValue) Option {
	values = appendIfNotIn(values, value)
	return func(p *Provider) error {
		p.config.DisplayValues = values
		return nil
	}
}

// WithAuthSessionLifetime sets the user authentication session lifetime.
// This defines how long an authorization request may last.
// The default is [defaultAuthnSessionTimeoutSecs].
func WithAuthSessionLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.AuthTimeoutSecs = secs
		return nil
	}
}

func WithAuthnSessionIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.AuthSessionIDFunc = f
		return nil
	}
}

// WithStaticClients adds static clients to the provider.
// The static clients are kept in memory only and are checked before consulting
// the client manager.
func WithStaticClients(c *goidc.Client, cs ...*goidc.Client) Option {
	cs = appendIfNotIn(cs, c)
	return func(p *Provider) error {
		p.config.StaticClients = cs
		return nil
	}
}

// WithPolicies adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func WithPolicies(policies ...goidc.AuthnPolicy) Option {
	return func(p *Provider) error {
		p.config.Policies = append(p.config.Policies, policies...)
		return nil
	}
}

// WithErrorRenderer defines a handler to be executed when the
// authorization request results in error, but the error can't be redirected.
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithErrorRenderer(render goidc.RenderErrorFunc) Option {
	return func(p *Provider) error {
		p.config.RenderErrorFunc = render
		return nil
	}
}

// WithErrorHandler defines a handler to be executed when an error happens.
// For instance, this can be used to log information about the error.
func WithErrorHandler(f goidc.HandleErrorFunc) Option {
	return func(p *Provider) error {
		p.config.HandleErrorFunc = f
		return nil
	}
}

// WithClientSecretVerifier replaces the default constant-time compare
// used to validate client_secret_basic and client_secret_post.
// This enables callers to store client secrets hashed at rest (bcrypt,
// argon2, HSM, etc.) by supplying a verifier that compares the hash.
// The verifier receives goidc.Client.Secret as the stored value, so the
// caller controls what that field holds.
// When unset, the default constant-time compare is used and Client.Secret
// is treated as plaintext.
// client_secret_jwt is unaffected: it reads Client.Secret directly as the
// HMAC signing key per RFC 7523 §2.2.
func WithClientSecretVerifier(f goidc.VerifyClientSecretFunc) Option {
	return func(p *Provider) error {
		p.config.VerifyClientSecretFunc = f
		return nil
	}
}

// WithJTIConsumer registers a function to validate JWT IDs (JTI) during JWT
// processing.
// This function is used to prevent replay attacks by ensuring that each JTI is
// unique and not reused.
func WithJTIConsumer(f goidc.ConsumeJTIFunc) Option {
	return func(p *Provider) error {
		p.config.ConsumeJTIFunc = f
		return nil
	}
}

// WithResourceIndicators enables client to indicate which resources they intend
// to access.
func WithResourceIndicators(resource string, resources ...string) Option {
	resources = appendIfNotIn(resources, resource)
	return func(p *Provider) error {
		p.config.ResourceIndicatorsIsEnabled = true
		p.config.Resources = resources
		return nil
	}
}

// WithResourceIndicatorsRequired makes resource indicators required.
// For more info, see [WithResourceIndicators].
func WithResourceIndicatorsRequired(resource string, resources ...string) Option {
	return func(p *Provider) error {
		p.config.ResourceIndicatorsIsRequired = true
		return WithResourceIndicators(resource, resources...)(p)
	}
}

// WithHTTPClient defines how to generate the client used to make HTTP
// requests to, for instance, a client's JWKS endpoint.
// By default, the provider uses an HTTP client with request, response header,
// and TLS handshake timeouts configured. The default client also does not
// follow redirects automatically.
func WithHTTPClientFunc(f goidc.HTTPClientFunc) Option {
	return func(p *Provider) error {
		p.config.HTTPClientFunc = f
		return nil
	}
}

// WithJARHTTPClientFunc defines how to generate the client used to fetch JAR
// request objects by reference via the "request_uri" authorization parameter.
// When unset, the provider falls back to [WithHTTPClientFunc].
func WithJARHTTPClientFunc(f goidc.HTTPClientFunc) Option {
	return func(p *Provider) error {
		p.config.JARHTTPClientFunc = f
		return nil
	}
}

// WithJWTBearerGrantClientAuthnRequired makes client authentication required
// for the jwt bearer grant type.
func WithJWTBearerGrantClientAuthnRequired() Option {
	return func(p *Provider) error {
		p.config.JWTBearerClientAuthnIsRequired = true
		return nil
	}
}

// WithSubIdentifierTypes sets the subject identifier types available for clients.
//
// If [goidc.SubIdentifierPairwise] is informed, the default behavior for
// generating pairwise subjects is to keep the value as is.
// This can be overridden with [WithPairwiseSubject].
func WithSubIdentifierTypes(defaultType goidc.SubIdentifierType, types ...goidc.SubIdentifierType) Option {
	types = appendIfNotIn(types, defaultType)
	return func(p *Provider) error {
		p.config.SubIdentifierTypeDefault = defaultType
		p.config.SubIdentifierTypes = types
		return nil
	}
}

func WithPairwiseSubject(f goidc.PairwiseSubjectFunc) Option {
	return func(p *Provider) error {
		p.config.PairwiseSubjectFunc = f
		return nil
	}
}

// WithSigner sets a custom signing function.
// This is required when the JWKS function returns only public keys and signing
// operations need to be handled separately.
func WithSigner(f goidc.SignerFunc) Option {
	return func(p *Provider) error {
		p.config.SignerFunc = f
		return nil
	}
}

// WithDecrypter sets a custom decryption function.
// This is required when the JWKS function returns only public keys and
// server-side encryption (e.g., JAR encryption) is enabled.
func WithDecrypter(f goidc.DecrypterFunc) Option {
	return func(p *Provider) error {
		p.config.DecrypterFunc = f
		return nil
	}
}

func WithErrorURI(uri string) Option {
	return func(p *Provider) error {
		p.config.ErrorURI = uri
		return nil
	}
}

// WithOpenIDFederation enables OpenID Federation support, allowing the provider
// to participate in a trust federation where trust relationships are established
// through signed entity statements rather than pre-configured client registrations.
//
// Parameters:
//   - manager: The storage used to persist federated clients. If nil, the
//     default in-memory storage is used.
//   - jwksFunc: A function that returns the provider's Federation JWKS, used to sign
//     the provider's entity configuration. This JWKS is separate from the provider's
//     regular signing keys. See [WithSigner] if the private keys are not available.
//   - authorityHints: Entity identifiers of immediate superiors that can issue
//     subordinate statements about this provider. These hints help relying parties
//     discover trust paths from this provider to a trusted anchor.
//   - trustedAnchors: A list of trust anchor entity IDs (URLs) that the provider
//     accepts when resolving trust chains for federated clients.
//
// Defaults:
//   - Client registration type: [goidc.ClientRegistrationTypeAutomatic] (see [WithOpenIDFedClientRegistrationTypes])
//   - Entity configuration endpoint: [defaultEndpointOpenIDFederation] (see [WithOpenIDFedRegistrationEndpoint])
//   - Signature algorithm: [defaultAsymmetricSigAlg] (see [WithOpenIDFedSignatureAlgs])
//   - Trust chain max depth: [defaultOpenIDFedTrustChainMaxDepth] (see [WithOpenIDFedTrustChainMaxDepth])
//
// [OpenID Federation specification]: https://openid.net/specs/openid-federation-1_0.html.
func WithOpenIDFederation(manager goidc.OpenIDFedManager, jwksFunc goidc.JWKSFunc, authorityHints []string, trustedAnchors []string) Option {
	return func(p *Provider) error {
		if len(authorityHints) == 0 {
			return errors.New("at least one authority hint is required")
		}
		if len(trustedAnchors) == 0 {
			return errors.New("at least one trusted anchor is required")
		}
		p.config.OpenIDFedIsEnabled = true
		p.config.OpenIDFedManager = manager
		p.config.OpenIDFedJWKSFunc = jwksFunc
		p.config.OpenIDFedAuthorityHints = authorityHints
		p.config.OpenIDFedTrustedAnchors = trustedAnchors
		return nil
	}
}

// WithOpenIDFedClientRegistrationTypes sets the client registration types available for the OpenID Federation.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedClientRegistrationTypes(typ goidc.ClientRegistrationType, types ...goidc.ClientRegistrationType) Option {
	types = appendIfNotIn(types, typ)
	return func(p *Provider) error {
		p.config.OpenIDFedClientRegTypes = types
		return nil
	}
}

// WithOpenIDFedSignatureAlgs sets the signature algorithms accepted to parse entity statements and trust marks.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedSignatureAlgs(defaultAlg goidc.SignatureAlgorithm, algs ...goidc.SignatureAlgorithm) Option {
	algs = appendIfNotIn(algs, defaultAlg)
	return func(p *Provider) error {
		p.config.OpenIDFedDefaultSigAlg = defaultAlg
		p.config.OpenIDFedSigAlgs = algs
		return nil
	}
}

// WithOpenIDFedSigner sets a custom signing function.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedSigner(f goidc.SignerFunc) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedSignerFunc = f
		return nil
	}
}

// WithOpenIDFedRequiredTrustMarks sets a custom function to determine the required trust marks for the OpenID Federation.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedRequiredTrustMarks(f goidc.RequiredTrustMarksFunc) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedRequiredTrustMarksFunc = f
		return nil
	}
}

// WithOpenIDFedRegistrationEndpoint sets the registration endpoint for the OpenID Federation.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedRegistrationEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedRegistrationEndpoint = endpoint
		return nil
	}
}

// WithOpenIDFedTrustChainMaxDepth sets the maximum depth of the trust chain for the OpenID Federation.
// For more information, see [WithOpenIDFederation].
func WithOpenIDFedTrustChainMaxDepth(depth int) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedTrustChainMaxDepth = depth
		return nil
	}
}

// WithOpenIDFedJWKSRepresentations sets the JWKS representations available for the Federation OpenID Provider.
// For more information, see [OpenID Fed §5.2.1].
func WithOpenIDFedJWKSRepresentations(rep goidc.JWKSRepresentation, reps ...goidc.JWKSRepresentation) Option {
	reps = appendIfNotIn(reps, rep)
	return func(p *Provider) error {
		p.config.OpenIDFedJWKSRepresentations = reps
		return nil
	}
}

// WithOpenIDFedSignedJWKSEndpoint sets the endpoint path for the signed JWKS.
// The signed JWKS is a JWT-wrapped representation of the provider's JWKS,
// providing integrity protection. This is used when [goidc.OpenIDFedJWKSRepresentationSignedURI]
// is enabled via [WithOpenIDFedJWKSRepresentations].
func WithOpenIDFedSignedJWKSEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedSignedJWKSEndpoint = endpoint
		return nil
	}
}

// WithOpenIDFedSignedJWKSLifetimeSecs sets the lifetime in seconds for signed JWKS JWTs.
// After this duration, the signed JWKS expires and must be re-fetched.
// If set to 0, the signed JWKS will not include an expiration claim.
func WithOpenIDFedSignedJWKSLifetimeSecs(secs int) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedSignedJWKSLifetimeSecs = secs
		return nil
	}
}

// WithOpenIDFedOrganizationName sets the human-readable organization name
// that appears in the provider's entity configuration metadata.
func WithOpenIDFedOrganizationName(name string) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedOrganizationName = name
		return nil
	}
}

// WithOpenIDFedHTTPClientFunc sets a custom HTTP client function for federation operations.
// This allows customization of HTTP requests made when fetching entity configurations,
// subordinate statements, and trust marks from other federation entities.
func WithOpenIDFedHTTPClientFunc(f goidc.HTTPClientFunc) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedHTTPClientFunc = f
		return nil
	}
}

// WithOpenIDFedClientHandler sets a custom function to handle the client during federation registration.
// See [WithOpenIDFederation].
func WithOpenIDFedClientHandler(f goidc.HandleClientFunc) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedHandleClientFunc = f
		return nil
	}
}

// WithOpenIDFedTrustMark configures trust marks that the provider will fetch and include
// in its entity configuration. Trust marks are credentials issued by accreditation
// authorities that attest to certain properties of the provider.
//
// Parameters:
//   - marks: A map of trust mark identifiers (e.g., "https://example.com/trust_marks/certified") to issuers.
func WithOpenIDFedTrustMark(marks map[goidc.TrustMark]string) Option {
	return func(p *Provider) error {
		p.config.OpenIDFedTrustMarks = marks
		return nil
	}
}

// WithLogout enables the [OpenID Connect RP-initiated logout flow](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
// The manager stores pending logout sessions while the flow is in progress. If
// manager is nil, the default in-memory storage is used.
// The default logout function is used when the flow is completed and the client
// does not provide a post_logout_redirect_uri. Use [WithLogoutPolicies] to
// configure which logout flows will be executed. The default logout session
// timeout is [defaultLogoutSessionTimeoutSecs].
func WithLogout(manager goidc.LogoutManager, handleFunc goidc.HandleDefaultPostLogoutFunc) Option {
	return func(p *Provider) error {
		p.config.LogoutIsEnabled = true
		p.config.LogoutManager = manager
		p.config.HandleDefaultPostLogoutFunc = handleFunc
		return nil
	}
}

// WithLogoutPolicies configures the logout policies that are evaluated for each
// RP-initiated logout request. The first policy whose setup function matches is
// used to execute the logout flow.
func WithLogoutPolicies(logoutPolicies ...goidc.LogoutPolicy) Option {
	return func(p *Provider) error {
		p.config.LogoutPolicies = logoutPolicies
		return nil
	}
}

// WithLogoutSessionTimeoutSecs sets the logout session timeout.
// For more information, see [WithLogout].
func WithLogoutSessionTimeoutSecs(secs int) Option {
	return func(p *Provider) error {
		p.config.LogoutSessionTimeoutSecs = secs
		return nil
	}
}

// WithLogoutEndpoint sets the logout endpoint.
// For more information, see [WithLogout].
func WithLogoutEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.LogoutEndpoint = endpoint
		return nil
	}
}

func WithLogoutSessionIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.LogoutSessionIDFunc = f
		return nil
	}
}

func WithJWTIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.JWTIDFunc = f
		return nil
	}
}

func WithAuthCodeFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.AuthCodeFunc = f
		return nil
	}
}

func WithAuthCodeLifetime(secs int) Option {
	return func(p *Provider) error {
		p.config.AuthCodeLifetimeSecs = secs
		return nil
	}
}

// WithSSF enables the Shared Signals Framework (SSF) support, allowing the provider
// to act as an SSF transmitter that publishes security events to receivers (relying parties).
// SSF enables real-time sharing of security-related signals such as session revocation,
// credential changes, and other CAEP (Continuous Access Evaluation Protocol) events.
//
// Parameters:
//   - jwksFunc: A function that returns the provider's SSF JWKS, used to sign
//     Security Event Tokens (SETs). This JWKS is separate from the provider's
//     regular signing keys.
//   - receiverFunc: A function that authenticates incoming requests and returns
//     the SSF receiver (relying party) information. This is called on every SSF
//     API request to identify and authorize the receiver.
//
// Defaults:
//   - Event stream manager: in-memory storage (see [WithSSFEventStreamManager])
//   - Signature algorithm: [defaultAsymmetricSigAlg]. The jwksFunc is supposed to have a key matching this algorithm.
//     See [WithSSFSignatureAlgorithm] to change the default.
//   - Status management: disabled (see [WithSSFEventStreamStatusManagement])
//   - Subject management: disabled (see [WithSSFEventStreamSubjectManagement])
//   - Verification: disabled (see [WithSSFEventStreamVerification])
//
// [OpenID Shared Signals Framework specification]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
func WithSSF(jwksFunc goidc.JWKSFunc, receiverFunc goidc.SSFAuthenticatedReceiverFunc) Option {
	return func(p *Provider) error {
		p.config.SSFIsEnabled = true
		p.config.SSFJWKSFunc = jwksFunc
		p.config.SSFAuthenticatedReceiverFunc = receiverFunc
		return nil
	}
}

func WithSSFSignatureAlgorithm(alg goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		p.config.SSFDefaultSigAlg = alg
		return nil
	}
}

// WithSSFEventTypes sets the default event types supported by the SSF transmitter.
// For more information, see [WithSSF].
func WithSSFEventTypes(eventType goidc.SSFEventType, events ...goidc.SSFEventType) Option {
	events = appendIfNotIn(events, eventType)
	return func(p *Provider) error {
		p.config.SSFEventsSupported = events
		return nil
	}
}

// WithSSFEventStreamManager replaces the default in-memory event stream storage.
// The event stream manager is responsible for persisting event stream configurations
// created by receivers. If manager is nil, the default in-memory storage is
// used.
// For more information, see [WithSSF].
func WithSSFEventStreamManager(manager goidc.SSFEventStreamManager) Option {
	return func(p *Provider) error {
		p.config.SSFEventStreamManager = manager
		return nil
	}
}

// WithSSFDeliveryMethods sets the delivery methods supported by the SSF transmitter.
// Supported methods are push (transmitter pushes events to receiver) and poll
// (receiver polls transmitter for events).
// For more information, see [WithSSF].
func WithSSFDeliveryMethods(method goidc.SSFDeliveryMethod, methods ...goidc.SSFDeliveryMethod) Option {
	methods = appendIfNotIn(methods, method)
	return func(p *Provider) error {
		p.config.SSFDeliveryMethods = methods
		return nil
	}
}

// WithSSFEventPollManager replaces the default in-memory poll event storage.
// The poll manager is responsible for queuing events for receivers using the poll
// delivery method and tracking acknowledgements. If manager is nil, the default
// in-memory storage is used.
// For more information, see [WithSSF].
func WithSSFEventPollManager(manager goidc.SSFEventPollManager) Option {
	return func(p *Provider) error {
		p.config.SSFEventPollManager = manager
		return nil
	}
}

// WithSSFEventStreamStatusManagement enables the stream status management API,
// allowing receivers to read and update the status of their event streams
// (e.g., enabled, paused, disabled).
// For more information, see [WithSSF].
func WithSSFEventStreamStatusManagement() Option {
	return func(p *Provider) error {
		p.config.SSFIsStatusManagementEnabled = true
		return nil
	}
}

// WithSSFEventStreamSubjectManagement enables the subject management API,
// allowing receivers to add or remove specific subjects they want to receive
// events for on a given stream.
// For more information, see [WithSSF].
func WithSSFEventStreamSubjectManagement() Option {
	return func(p *Provider) error {
		p.config.SSFIsSubjectManagementEnabled = true
		return nil
	}
}

// WithSSFStatusEndpoint overrides the default endpoint for stream status management.
// For more information, see [WithSSFEventStreamStatusManagement].
func WithSSFStatusEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.SSFStatusEndpoint = endpoint
		return nil
	}
}

// WithSSFAddSubjectEndpoint overrides the default endpoint for adding subjects to a stream.
// For more information, see [WithSSFEventStreamSubjectManagement].
func WithSSFAddSubjectEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.SSFAddSubjectEndpoint = endpoint
		return nil
	}
}

// WithSSFRemoveSubjectEndpoint overrides the default endpoint for removing subjects from a stream.
// For more information, see [WithSSFEventStreamSubjectManagement].
func WithSSFRemoveSubjectEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.SSFRemoveSubjectEndpoint = endpoint
		return nil
	}
}

// WithSSFEventStreamVerification enables the verification API, allowing receivers
// to request verification events to confirm the stream is working correctly.
// The transmitter responds by sending a verification event with an optional state value.
// If the function is nil, the provider will use the default in memory verification implementation.
// For more information, see [WithSSF].
func WithSSFEventStreamVerification(f goidc.SSFScheduleVerificationEventFunc) Option {
	return func(p *Provider) error {
		p.config.SSFIsVerificationEnabled = true
		p.config.SSFScheduleVerificationEventFunc = f
		return nil
	}
}

// WithSSFMinVerificationInterval sets the minimum interval (in seconds) between
// verification requests from the same receiver. This prevents abuse of the verification endpoint.
// For more information, see [WithSSFEventStreamVerification].
func WithSSFMinVerificationInterval(secs int) Option {
	return func(p *Provider) error {
		p.config.SSFMinVerificationInterval = secs
		return nil
	}
}

// WithSSFDefaultSubjects indicates how subjects are handled when a stream is created.
// Use [goidc.SSFDefaultSubjectAll] when automatically including all subjects by default, or
// [goidc.SSFDefaultSubjectNone] when requiring explicit subject registration via the subject management API.
// For more information, see [WithSSF].
func WithSSFDefaultSubjects(defaultSubjects goidc.SSFDefaultSubject) Option {
	return func(p *Provider) error {
		p.config.SSFDefaultSubjects = defaultSubjects
		return nil
	}
}

// WithSSFCriticalSubjectMembers sets the subject identifier members that must be processed by the receiver.
// For more information, see [WithSSF].
func WithSSFCriticalSubjectMembers(sub string, subs ...string) Option {
	subs = appendIfNotIn(subs, sub)
	return func(p *Provider) error {
		p.config.SSFCriticalSubjectMembers = subs
		return nil
	}
}

// WithSSFAuthorizationSchemes sets the authorization schemes published in the SSF
// configuration endpoint. This informs receivers how to authenticate when calling
// the SSF APIs (e.g., Bearer tokens, OAuth 2.0).
// For more information, see [WithSSF].
func WithSSFAuthorizationSchemes(scheme goidc.SSFAuthorizationScheme, schemes ...goidc.SSFAuthorizationScheme) Option {
	schemes = appendIfNotIn(schemes, scheme)
	return func(p *Provider) error {
		p.config.SSFAuthorizationSchemes = schemes
		return nil
	}
}

// WithSSFHTTPClientFunc sets a custom HTTP client factory for SSF push delivery.
// This is used when the transmitter pushes events to receiver endpoints.
// For more information, see [WithSSF].
func WithSSFHTTPClientFunc(f goidc.HTTPClientFunc) Option {
	return func(p *Provider) error {
		p.config.SSFHTTPClientFunc = f
		return nil
	}
}

// WithSSFInactivityTimeoutSecs sets the inactivity timeout for event streams.
// [SSF 1.0 §8.1.1] If a stream has no activity for this duration, the handleFunc
// is called to handle the expired stream (e.g., pause or delete it).
// For more information, see [WithSSF].
func WithSSFInactivityTimeoutSecs(secs int, handleFunc goidc.SSFHandleExpiredEventStreamFunc) Option {
	return func(p *Provider) error {
		p.config.SSFInactivityTimeoutSecs = secs
		p.config.SSFHandleExpiredEventStreamFunc = handleFunc
		return nil
	}
}

// WithSSFMultipleStreamsPerReceiver controls whether a single receiver
// can create multiple event streams.
// For more information, see [WithSSF].
func WithSSFMultipleStreamsPerReceiver() Option {
	return func(p *Provider) error {
		p.config.SSFMultipleStreamsPerReceiverIsEnabled = true
		return nil
	}
}

func WithCredentialIssuers(issuers ...goidc.VCIssuer) Option {
	return func(p *Provider) error {
		p.config.VCIsEnabled = true
		p.config.VCIssuers = issuers
		return nil
	}
}

// appendIfNotIn adds 'value' to the beginning of 'values' if it is not already present.
func appendIfNotIn[T comparable](values []T, newValues ...T) []T {
	for _, v := range slices.Backward(newValues) {
		if !slices.Contains(values, v) {
			values = append([]T{v}, values...)
		}
	}
	return values
}
