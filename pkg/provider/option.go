package provider

import (
	"errors"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Option func(p *Provider) error

// ── Profile ───────────────────────────────────────────────────────────────────

// ProfileOption is an option for [WithProfile].
type ProfileOption Option

// WithProfile adjusts the server's behavior for non-configurable settings,
// ensuring compliance with the associated specification. Depending on
// the profile selected, the server may modify its operations to meet specific
// requirements dictated by the corresponding standards or protocols.
func WithProfile(profile goidc.Profile, opts ...ProfileOption) Option {
	return func(p *Provider) error {
		p.config.Profile = profile
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithProfileValidation enables validation of the provider configuration against
// the selected profile.
func WithProfileValidation() ProfileOption {
	return func(p *Provider) error {
		p.profileValidationEnabled = true
		return nil
	}
}

// ── General ───────────────────────────────────────────────────────────────────

// WithPathPrefix defines a shared prefix for all endpoints.
// When using the provider http handler directly, the path prefix must be added
// to the router.
//
//	op, err := provider.New(
//		provider.Config{
//			Issuer:      "http://example.com",
//			JWKSFunc:    jwksFunc,
//			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.RS256},
//		},
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

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is [defaultEndpointUserInfo].
func WithUserInfoEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.UserInfoEndpoint = endpoint
		return nil
	}
}

// WithTokenIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is [defaultEndpointTokenIntrospection].
// To enable token introspection, see [WithTokenIntrospection].
func WithTokenIntrospectionEndpoint(endpoint string) Option {
	return func(p *Provider) error {
		p.config.TokenIntrospectionEndpoint = endpoint
		return nil
	}
}

// WithHTTPClientFunc defines how to generate the client used to make HTTP
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

// WithErrorURI sets the URI that will be included in error responses to
// provide additional information about the error.
func WithErrorURI(uri string) Option {
	return func(p *Provider) error {
		p.config.ErrorURI = uri
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

// WithGrantIDFunc sets the function used to generate grant IDs.
func WithGrantIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.GrantIDFunc = f
		return nil
	}
}

// WithJWTIDFunc sets the function used to generate JWT IDs.
func WithJWTIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.JWTIDFunc = f
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

// ── Scopes & Claims ───────────────────────────────────────────────────────────

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

// WithOpenIDScopeRequired forces the openid scope to be informed in all
// the authorization requests.
func WithOpenIDScopeRequired() Option {
	return func(p *Provider) error {
		p.config.OpenIDRequired = true
		return nil
	}
}

// WithClaims signals support for user claims.
// The claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared in the field "claims_supported" of the
// openid configuration endpoint response.
// The default value for "claim_types_supported" is set to "normal".
// To define other claim types, see [WithClaimTypes].
func WithClaims(claims ...string) Option {
	return func(p *Provider) error {
		if len(claims) == 0 {
			return errors.New("at least one claim is required")
		}
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
		return nil
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The values provided are published at "claim_types_supported".
// To add support for claims, see [WithClaims].
func WithClaimTypes(claimTypes ...goidc.ClaimType) Option {
	return func(p *Provider) error {
		if len(claimTypes) == 0 {
			return errors.New("at least one claim type is required")
		}
		p.config.ClaimTypes = claimTypes
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

// ── Subject Identifiers ───────────────────────────────────────────────────────

// SubjectIdentifierOption is an option for [WithSubjectIdentifiers].
type SubjectIdentifierOption Option

// WithSubjectIdentifiers sets the subject identifier types available for clients.
// The first element is used as the default subject identifier type.
// If [goidc.SubIdentifierPairwise] is included, [WithPairwiseSubjectFunc] is required.
func WithSubjectIdentifiers(types []goidc.SubIdentifierType, opts ...SubjectIdentifierOption) Option {
	return func(p *Provider) error {
		if len(types) == 0 {
			return errors.New("at least one subject identifier type is required")
		}
		p.config.SubIdentifierTypeDefault = types[0]
		p.config.SubIdentifierTypes = types
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		if slices.Contains(types, goidc.SubIdentifierPairwise) && p.config.PairwiseSubjectFunc == nil {
			return errors.New("a pairwise subject function is required when pairwise subject identifier type is enabled")
		}
		return nil
	}
}

// WithPairwiseSubjectFunc sets the function used to generate pairwise subject identifiers.
func WithPairwiseSubjectFunc(f goidc.PairwiseSubjectFunc) SubjectIdentifierOption {
	return func(p *Provider) error {
		p.config.PairwiseSubjectFunc = f
		return nil
	}
}

// ── Client Authentication ─────────────────────────────────────────────────────

// WithDefaultAuthn sets the default client authentication method used when a
// client does not explicitly specify one.
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
func WithPrivateKeyJWTAuthn(algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one signature algorithm is required for private_key_jwt")
		}
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
func WithSecretJWTAuthn(algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one signature algorithm is required for client_secret_jwt")
		}
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

// WithTLSAuthn enables the "tls_client_auth" client authentication method.
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
func WithAttestationJWTAuthn(issuers ...goidc.AttestationIssuer) Option {
	return func(p *Provider) error {
		if len(issuers) == 0 {
			return errors.New("at least one attestation issuer is required")
		}
		p.config.AuthnMethods = append(p.config.AuthnMethods, goidc.AuthnMethodAttestationJWT)
		p.config.AuthnMethodAttestationJWTIssuers = issuers
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

// ── ID Token ──────────────────────────────────────────────────────────────────

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
func WithIDTokenEncryption(algs ...goidc.KeyEncryptionAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one key encryption algorithm is required for ID token encryption")
		}
		p.config.IDTokenEncEnabled = true
		p.config.IDTokenKeyEncAlgs = algs
		return nil
	}
}

// WithIDTokenContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// The first element is used as the default content encryption algorithm.
// To enable encryption of ID tokens, see [WithIDTokenEncryption].
func WithIDTokenContentEncryptionAlgs(algs ...goidc.ContentEncryptionAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one content encryption algorithm is required")
		}
		p.config.IDTokenDefaultContentEncAlg = algs[0]
		p.config.IDTokenContentEncAlgs = algs
		return nil
	}
}

// ── User Info ─────────────────────────────────────────────────────────────────

// WithUserInfoSignatureAlgs sets the algorithms available to sign the user info
// endpoint response.
// The first element is used as the default signing algorithm.
func WithUserInfoSignatureAlgs(algs ...goidc.SignatureAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one signature algorithm is required for user info")
		}
		p.config.UserInfoDefaultSigAlg = algs[0]
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
func WithUserInfoEncryption(algs ...goidc.KeyEncryptionAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one key encryption algorithm is required for user info encryption")
		}
		p.config.UserInfoEncEnabled = true
		p.config.UserInfoKeyEncAlgs = algs
		return nil
	}
}

// WithUserInfoContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// The first element is used as the default content encryption algorithm.
// To enable encryption of user information, see [WithUserInfoEncryption].
func WithUserInfoContentEncryptionAlgs(algs ...goidc.ContentEncryptionAlgorithm) Option {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one content encryption algorithm is required")
		}
		p.config.UserInfoDefaultContentEncAlg = algs[0]
		p.config.UserInfoContentEncAlgs = algs
		return nil
	}
}

// ── Access Token ──────────────────────────────────────────────────────────────

// TokenOption is an option for [WithTokenOptions].
type TokenOption Option

// WithTokenOptions configures how access tokens are issued by the provider.
//
// It is called for each issuance and can choose, for example, the token format
// (opaque or JWT) and token lifetime based on the grant and client.
//
// If pairwise subject identifiers are enabled and applicable to the subject,
// the token will be issued as an opaque token even when the token option is set
// to issue a JWT token. Opaque tokens require [WithOpaqueTokens] to be enabled.
func WithTokenOptions(tokenOpts goidc.TokenOptionsFunc, opts ...TokenOption) Option {
	return func(p *Provider) error {
		p.config.TokenOptionsFunc = tokenOpts
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithOpaqueTokens enables opaque access token storage and retrieval.
// If manager is nil, the default in-memory storage is used.
func WithOpaqueTokens(manager goidc.OpaqueTokenManager) TokenOption {
	return func(p *Provider) error {
		p.config.OpaqueTokenEnabled = true
		p.config.OpaqueTokenManager = manager
		return nil
	}
}

// WithOpaqueTokenFunc sets the function to generate opaque access tokens.
func WithOpaqueTokenFunc(f goidc.OpaqueTokenFunc) TokenOption {
	return func(p *Provider) error {
		p.config.OpaqueTokenFunc = f
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

// ── Authorization Code Grant ──────────────────────────────────────────────────

// AuthCodeGrantOption is an option for [WithAuthCodeGrant].
type AuthCodeGrantOption Option

// AuthCodeGrantConfig holds the required configuration for the authorization code grant.
type AuthCodeGrantConfig struct {
	// Manager persists authorization sessions. If nil, the default in-memory
	// storage is used.
	Manager goidc.AuthManager
	// ResponseTypes are the response types accepted at the authorization
	// endpoint. They determine which flows are available:
	//   - code enables the authorization code flow
	//   - token and id_token enable implicit flows
	//   - combined types such as code id_token enable hybrid flows
	ResponseTypes []goidc.ResponseType
}

// WithAuthCodeGrant enables the authorization endpoint flows backed by
// authentication sessions.
//
// It always enables the authorization_code grant type and registers the
// response types accepted at the authorization endpoint.
// If any implicit or hybrid response type is informed, the provider also adds
// the implicit grant type internally.
func WithAuthCodeGrant(cfg AuthCodeGrantConfig, opts ...AuthCodeGrantOption) Option {
	return func(p *Provider) error {
		if len(cfg.ResponseTypes) == 0 {
			return errors.New("at least one response type is required for the authorization code grant")
		}
		p.config.AuthManager = cfg.Manager
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantAuthorizationCode)
		p.config.ResponseTypes = append(p.config.ResponseTypes, cfg.ResponseTypes...)
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithAuthCodeFunc sets the function to generate authorization codes.
func WithAuthCodeFunc(f goidc.RandomFunc) AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.AuthCodeFunc = f
		return nil
	}
}

// WithAuthCodeLifetime sets the authorization code lifetime in seconds.
func WithAuthCodeLifetime(secs int) AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.AuthCodeLifetimeSecs = secs
		return nil
	}
}

// WithAuthPolicies adds authentication policies evaluated during authorization
// endpoint requests.
func WithAuthPolicies(policies ...goidc.AuthnPolicy) AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.AuthPolicies = append(p.config.AuthPolicies, policies...)
		return nil
	}
}

// WithAuthnSessionIDFunc sets the function used to generate authentication session IDs.
func WithAuthnSessionIDFunc(f goidc.RandomFunc) Option {
	return func(p *Provider) error {
		p.config.AuthSessionIDFunc = f
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

// WithFormPostResponseMode enables support for the `form_post` response mode
// at the authorization endpoint.
func WithFormPostResponseMode() AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.ResponseModes = append(p.config.ResponseModes, goidc.ResponseModeFormPost)
		return nil
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.IssuerRespParamEnabled = true
		return nil
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.ClaimsParamEnabled = true
		return nil
	}
}

// PKCEOption is an option for [WithPKCE].
type PKCEOption Option

// WithPKCE makes proof key for code exchange available to clients.
// The first element of methods is used as the default challenge method.
func WithPKCE(methods []goidc.CodeChallengeMethod, opts ...PKCEOption) AuthCodeGrantOption {
	return func(p *Provider) error {
		if len(methods) == 0 {
			return errors.New("at least one code challenge method is required for PKCE")
		}
		p.config.PKCEEnabled = true
		p.config.PKCEDefaultChallengeMethod = methods[0]
		p.config.PKCEChallengeMethods = methods
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithPKCERequired makes proof key for code exchange required.
func WithPKCERequired() PKCEOption {
	return func(p *Provider) error {
		p.config.PKCERequired = true
		return nil
	}
}

// PAROption is an optional configuration for Pushed Authorization Requests.
// See [WithPAR] for more information.
type PAROption Option

// WithPAR allows authorization flows to start at the pushed authorization
// request endpoint.
//
// The manager stores the pushed authorization request session that will later
// be resolved by `request_uri` at the authorization endpoint. If manager is
// nil, the default in-memory storage is used.
func WithPAR(manager goidc.PARManager, opts ...PAROption) AuthCodeGrantOption {
	return func(p *Provider) error {
		p.config.PAREnabled = true
		p.config.PARManager = manager
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
func WithPARRequired() PAROption {
	return func(p *Provider) error {
		p.config.PARRequired = true
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is [defaultEndpointPushedAuthorizationRequest].
func WithPAREndpoint(endpoint string) PAROption {
	return func(p *Provider) error {
		p.config.PAREndpoint = endpoint
		return nil
	}
}

// WithPARSessionHandler sets the function called when a new PAR session is created.
func WithPARSessionHandler(f goidc.HandleSessionFunc) PAROption {
	return func(p *Provider) error {
		p.config.PARHandleSessionFunc = f
		return nil
	}
}

// WithPARLifetime sets the PAR session lifetime in seconds.
func WithPARLifetime(secs int) PAROption {
	return func(p *Provider) error {
		p.config.PARLifetimeSecs = secs
		return nil
	}
}

// WithPARUnregisteredRedirectURIs allows clients to inform unregistered
// redirect URIs during requests to pushed authorization endpoint.
func WithPARUnregisteredRedirectURIs() PAROption {
	return func(p *Provider) error {
		p.config.PARUnregisteredRedirectURIEnabled = true
		return nil
	}
}

// WithPARIDFunc sets the function used to generate PAR request IDs.
func WithPARIDFunc(f goidc.RandomFunc) PAROption {
	return func(p *Provider) error {
		p.config.PARIDFunc = f
		return nil
	}
}

// JAROption is an optional configuration for JWT-Secured Authorization Requests.
// See [WithJAR] for more information.
type JAROption Option

// WithJAR allows authorization requests to be securely sent as signed JWTs.
// Clients can choose the signing algorithm by setting the attribute
// "request_object_signing_alg".
// By default, the max difference between "iat" and "exp" of request objects is
// set to [defaultJWTLifetimeSecs].
func WithJAR(sigAlgs []goidc.SignatureAlgorithm, opts ...JAROption) AuthCodeGrantOption {
	return func(p *Provider) error {
		if len(sigAlgs) == 0 {
			return errors.New("at least one signature algorithm is required for JAR")
		}
		p.config.JAREnabled = true
		p.config.JARSigAlgs = sigAlgs
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
func WithJARRequired() JAROption {
	return func(p *Provider) error {
		p.config.JARRequired = true
		return nil
	}
}

// WithJARByReference enables support for request objects referenced by the
// "request_uri" authorization parameter. The httpClientFunc defines how to
// generate the HTTP client used to fetch request objects. If nil, the provider
// falls back to [WithHTTPClientFunc].
func WithJARByReference(httpClientFunc goidc.HTTPClientFunc) JAROption {
	return func(p *Provider) error {
		p.config.JARByReferenceEnabled = true
		p.config.JARByReferenceHTTPClientFunc = httpClientFunc
		return nil
	}
}

// WithJARByReferenceUnregisteredURIs allows request_uri values that were not
// pre-registered by the client.
// Avoid using this option when possible, as it expands the attack surface for
// server-side request_uri fetches.
func WithJARByReferenceUnregisteredURIs() JAROption {
	return func(p *Provider) error {
		p.config.JARByReferenceUnregisteredURIEnabled = true
		return nil
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
func WithJAREncryption(algs ...goidc.KeyEncryptionAlgorithm) JAROption {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one key encryption algorithm is required for JAR encryption")
		}
		p.config.JAREncEnabled = true
		p.config.JARKeyEncAlgs = algs
		return nil
	}
}

// WithJARContentEncryptionAlgs overrides the default content encryption
// algorithm for request objects which is A128CBC-HS256.
func WithJARContentEncryptionAlgs(algs ...goidc.ContentEncryptionAlgorithm) JAROption {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one content encryption algorithm is required")
		}
		p.config.JARContentEncAlgs = algs
		return nil
	}
}

// JARMOption is an optional configuration for JWT-Secured Authorization Response Mode.
// See [WithJARM] for more information.
type JARMOption Option

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// The first algorithm in sigAlgs is used as the default signing algorithm.
// Clients can choose the algorithm by setting the attribute
// "authorization_signed_response_alg".
// By default, the lifetime of a response object is [defaultJWTLifetimeSecs].
func WithJARM(sigAlgs []goidc.SignatureAlgorithm, opts ...JARMOption) AuthCodeGrantOption {
	return func(p *Provider) error {
		if len(sigAlgs) == 0 {
			return errors.New("at least one signature algorithm is required for JARM")
		}
		if slices.Contains(sigAlgs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for JARM")
		}
		p.config.JARMEnabled = true
		p.config.JARMSigAlgDefault = sigAlgs[0]
		p.config.JARMSigAlgs = sigAlgs
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithJARMEncryption allows responses for authorization requests to be sent as encrypted JWTs.
// The default content encryption algorithm is A128CBC-HS256.
// Clients can choose the encryption algorithms by setting the attributes
// "authorization_encrypted_response_alg" and "authorization_encrypted_response_enc".
func WithJARMEncryption(algs ...goidc.KeyEncryptionAlgorithm) JARMOption {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one key encryption algorithm is required for JARM encryption")
		}
		p.config.JARMEncEnabled = true
		p.config.JARMKeyEncAlgs = algs
		return nil
	}
}

// WithJARMContentEncryptionAlgs overrides the default content encryption
// algorithm which is A128CBC-HS256.
// The first element is used as the default content encryption algorithm.
func WithJARMContentEncryptionAlgs(algs ...goidc.ContentEncryptionAlgorithm) JARMOption {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one content encryption algorithm is required")
		}
		p.config.JARMContentEncAlgDefault = algs[0]
		p.config.JARMContentEncAlgs = algs
		return nil
	}
}

// ── Refresh Token Grant ───────────────────────────────────────────────────────

// RefreshTokenOption is an optional configuration for the refresh token grant.
// See [WithRefreshTokenGrant] for more information.
type RefreshTokenOption Option

// WithRefreshTokenGrant enables the `refresh_token` grant type.
//
// Refresh token requests do not create a new authorization. Instead, they load
// an existing grant by its refresh token and issue a new access token under the
// same grant.
//
// The manager is used to resolve grants by refresh token. If manager is nil,
// the default in-memory storage is used.
func WithRefreshTokenGrant(manager goidc.RefreshTokenManager, opts ...RefreshTokenOption) Option {
	return func(p *Provider) error {
		p.config.RefreshTokenManager = manager
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithRefreshTokenShouldIssue sets the function that determines whether a refresh
// token should be issued.
func WithRefreshTokenShouldIssue(f goidc.RefreshTokenShouldIssueFunc) RefreshTokenOption {
	return func(p *Provider) error {
		p.config.RefreshTokenShouldIssueFunc = f
		return nil
	}
}

// WithRefreshTokenFunc sets the function used to generate refresh tokens.
func WithRefreshTokenFunc(f goidc.RandomFunc) RefreshTokenOption {
	return func(p *Provider) error {
		p.config.RefreshTokenFunc = f
		return nil
	}
}

// WithRefreshTokenLifetime sets the refresh token lifetime in seconds.
// A value of 0 means issued refresh tokens do not expire.
func WithRefreshTokenLifetime(secs int) RefreshTokenOption {
	return func(p *Provider) error {
		p.config.RefreshTokenLifetimeSecs = secs
		return nil
	}
}

// WithRefreshTokenRotation causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenRotation() RefreshTokenOption {
	return func(p *Provider) error {
		p.config.RefreshTokenRotationEnabled = true
		return nil
	}
}

// ── Client Credentials Grant ──────────────────────────────────────────────────

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

// ── JWT Bearer Grant ──────────────────────────────────────────────────────────

// JWTBearerGrantOption is an option for [WithJWTBearerGrant].
type JWTBearerGrantOption Option

// WithJWTBearerGrant enables the `urn:ietf:params:oauth:grant-type:jwt-bearer`
// grant type.
//
// The handler receives the raw assertion from the token request and must
// validate it according to the deployment rules. If the assertion is accepted,
// it returns the subject represented by that assertion so the provider can
// create a grant and issue a token from it.
func WithJWTBearerGrant(f goidc.JWTBearerHandleAssertionFunc, opts ...JWTBearerGrantOption) Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantJWTBearer)
		p.config.JWTBearerHandleAssertionFunc = f
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithJWTBearerClientAuthnRequired makes client authentication required
// for the JWT bearer grant type.
func WithJWTBearerClientAuthnRequired() JWTBearerGrantOption {
	return func(p *Provider) error {
		p.config.JWTBearerClientAuthnRequired = true
		return nil
	}
}

// ── Token Exchange Grant ──────────────────────────────────────────────────────

// TokenExchangeGrantOption is an option for [WithTokenExchangeGrant].
type TokenExchangeGrantOption Option

// WithTokenExchangeGrant enables the token exchange grant type (RFC 8693).
//
// The handler receives the token exchange request parameters and must validate
// the subject and actor tokens according to the deployment rules. It returns
// the subject to use for the resulting grant.
func WithTokenExchangeGrant(f goidc.TokenExchangeHandleFunc, opts ...TokenExchangeGrantOption) Option {
	return func(p *Provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantTokenExchange)
		p.config.TokenExchangeHandleFunc = f
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithTokenExchangeClientAuthnRequired makes client authentication required
// for the token exchange grant type.
func WithTokenExchangeClientAuthnRequired() TokenExchangeGrantOption {
	return func(p *Provider) error {
		p.config.TokenExchangeClientAuthnRequired = true
		return nil
	}
}

// ── Device Grant ──────────────────────────────────────────────────────────────

// DeviceGrantOption is an optional configuration for the device authorization grant.
// See [WithDeviceGrant] for more information.
type DeviceGrantOption Option

// DeviceGrantConfig holds the required configuration for the device authorization grant.
type DeviceGrantConfig struct {
	// Manager persists device authorization sessions. If nil, the default
	// in-memory storage is used.
	Manager goidc.DeviceAuthManager
	// PromptFunc renders the page where the user enters the device user code.
	PromptFunc goidc.RenderFunc
	// ConfirmationFunc renders the page shown to the user after successfully
	// entering the device user code.
	ConfirmationFunc goidc.RenderFunc
}

// WithDeviceGrant enables the device authorization grant.
func WithDeviceGrant(cfg DeviceGrantConfig, opts ...DeviceGrantOption) Option {
	return func(p *Provider) error {
		if cfg.PromptFunc == nil {
			return errors.New("the device grant prompt function cannot be nil")
		}
		if cfg.ConfirmationFunc == nil {
			return errors.New("the device grant confirmation function cannot be nil")
		}
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantDeviceCode)
		p.config.DeviceAuthManager = cfg.Manager
		p.config.DeviceAuthPromptUserCodeFunc = cfg.PromptFunc
		p.config.DeviceAuthRenderConfirmationFunc = cfg.ConfirmationFunc
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithDeviceCodeFunc sets the function used to generate device codes.
func WithDeviceCodeFunc(f goidc.RandomFunc) DeviceGrantOption {
	return func(p *Provider) error {
		p.config.DeviceCodeFunc = f
		return nil
	}
}

// WithDevicePolicies adds authentication policies evaluated during device
// authorization requests.
func WithDevicePolicies(policies ...goidc.AuthnPolicy) DeviceGrantOption {
	return func(p *Provider) error {
		p.config.DevicePolicies = append(p.config.DevicePolicies, policies...)
		return nil
	}
}

// ── CIBA Grant ────────────────────────────────────────────────────────────────

// CIBAOption is an optional configuration for Client-Initiated Backchannel Authentication.
// See [WithCIBAGrant] for more information.
type CIBAOption Option

// CIBAGrantConfig holds the required configuration for the CIBA grant.
type CIBAGrantConfig struct {
	// Manager persists pending CIBA sessions. If nil, the default in-memory
	// storage is used.
	Manager goidc.CIBAManager
	// DeliveryModes are the token delivery modes supported by the provider.
	DeliveryModes []goidc.CIBATokenDeliveryMode
}

// WithCIBAGrant enables the CIBA grant type.
func WithCIBAGrant(cfg CIBAGrantConfig, opts ...CIBAOption) Option {
	return func(p *Provider) error {
		if len(cfg.DeliveryModes) == 0 {
			return errors.New("at least one CIBA token delivery mode is required")
		}
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantCIBA)
		p.config.CIBAManager = cfg.Manager
		p.config.CIBATokenDeliveryModes = cfg.DeliveryModes
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithCIBAProfile sets the CIBA profile.
func WithCIBAProfile(profile goidc.CIBAProfile) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAProfile = profile
		return nil
	}
}

// WithCIBAEndpoint overrides the default value for the CIBA endpoint which is [defaultEndpointCIBA].
func WithCIBAEndpoint(endpoint string) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAEndpoint = endpoint
		return nil
	}
}

// WithCIBASessionHandler sets the function called when a new CIBA session is created.
func WithCIBASessionHandler(f goidc.HandleSessionFunc) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAHandleSessionFunc = f
		return nil
	}
}

// WithCIBAHTTPClientFunc sets a custom HTTP client function for outbound CIBA
// client notifications in ping and push delivery modes. When unset, the
// provider falls back to [WithHTTPClientFunc].
func WithCIBAHTTPClientFunc(f goidc.HTTPClientFunc) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAHTTPClientFunc = f
		return nil
	}
}

// WithCIBAJAR enables JAR for CIBA requests.
func WithCIBAJAR(sigAlgs []goidc.SignatureAlgorithm) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAJAREnabled = true
		p.config.CIBAJARSigAlgs = sigAlgs
		return nil
	}
}

// WithCIBAJARRequired enables and requires JAR for CIBA requests.
func WithCIBAJARRequired(sigAlgs []goidc.SignatureAlgorithm) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAJARRequired = true
		return WithCIBAJAR(sigAlgs)(p)
	}
}

// WithCIBAUserCode enables user code support for CIBA.
func WithCIBAUserCode() CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAUserCodeEnabled = true
		return nil
	}
}

// WithCIBAPollingInterval sets the polling interval in seconds for CIBA poll mode.
func WithCIBAPollingInterval(interval int) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAPollingIntervalSecs = interval
		return nil
	}
}

// WithCIBALifetime sets the default CIBA session lifetime in seconds.
func WithCIBALifetime(secs int) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBADefaultSessionLifetimeSecs = secs
		return nil
	}
}

// WithCIBAIDFunc sets the function used to generate CIBA auth request IDs.
func WithCIBAIDFunc(f goidc.RandomFunc) CIBAOption {
	return func(p *Provider) error {
		p.config.CIBAIDFunc = f
		return nil
	}
}

// ── DCR ───────────────────────────────────────────────────────────────────────

// DCROption is an optional configuration for Dynamic Client Registration.
// See [WithDCR] for more information.
type DCROption Option

// WithDCR enables Dynamic Client Registration (RFC 7591).
// The manager is used to persist dynamically registered clients.
// If manager is nil, the default in-memory storage is used.
//
// Production deployments should typically combine this option with
// [WithDCRInitialTokenValidator] and/or [WithDCRClientHandler] to enforce
// their registration policy.
func WithDCR(manager goidc.DCRManager, opts ...DCROption) Option {
	return func(p *Provider) error {
		p.config.DCREnabled = true
		p.config.DCRManager = manager
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is [defaultEndpointDynamicClient].
func WithDCREndpoint(endpoint string) DCROption {
	return func(p *Provider) error {
		p.config.DCREndpoint = endpoint
		return nil
	}
}

// WithDCRClientHandler installs custom logic for DCR and DCM requests.
//
// Use it to enforce registration rules, validate metadata, reject unwanted
// clients, or apply default values during create and update requests.
func WithDCRClientHandler(f goidc.DCRHandleClientFunc) DCROption {
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
func WithDCRInitialTokenValidator(f goidc.DCRValidateInitialTokenFunc) DCROption {
	return func(p *Provider) error {
		p.config.DCRValidateInitialTokenFunc = f
		return nil
	}
}

// WithDCRRegistrationTokenFunc customizes the registration access token issued
// for DCR and DCM operations.
func WithDCRRegistrationTokenFunc(f goidc.RandomFunc) DCROption {
	return func(p *Provider) error {
		p.config.DCRRegistrationTokenFunc = f
		return nil
	}
}

// WithDCRClientID sets the function used to generate client IDs for dynamically
// registered clients.
func WithDCRClientID(f goidc.ClientIDFunc) DCROption {
	return func(p *Provider) error {
		p.config.DCRClientIDFunc = f
		return nil
	}
}

// WithDCRTokenRotation makes the registration access token rotate during client
// read and update requests.
func WithDCRTokenRotation() DCROption {
	return func(p *Provider) error {
		p.config.DCRTokenRotationEnabled = true
		return nil
	}
}

// WithDCRSecretRotation makes client secrets rotate during client read and
// update requests when the client uses a secret-based authentication method.
func WithDCRSecretRotation() DCROption {
	return func(p *Provider) error {
		p.config.DCRSecretRotationEnabled = true
		return nil
	}
}

// WithDCRSecretLifetime sets the client secret lifetime in seconds for
// dynamically registered clients that use a secret-based authentication method.
// A value of 0 means the issued client secret does not expire.
func WithDCRSecretLifetime(secs int) DCROption {
	return func(p *Provider) error {
		p.config.DCRSecretLifetimeSecs = secs
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
		p.config.RPMetadataChoicesEnabled = true
		return nil
	}
}

// ── Token Introspection ───────────────────────────────────────────────────────

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
		p.config.TokenIntrospectionEnabled = true
		p.config.TokenIntrospectionIsClientAllowedFunc = f
		return nil
	}
}

// ── Token Revocation ──────────────────────────────────────────────────────────

// TokenRevocationOption is an option for [WithTokenRevocation].
type TokenRevocationOption Option

// WithTokenRevocation allows clients to revoke tokens.
//
// Refresh token revocation always invalidates the underlying grant and related
// access tokens. For opaque access tokens, revocation revokes only the
// presented token unless [WithTokenRevocationRevokeGrantOnAccessToken] is also
// enabled. For JWT access tokens, revocation is only effective when
// [WithTokenRevocationRevokeGrantOnAccessToken] is enabled, since JWTs are not
// stored server-side.
func WithTokenRevocation(f goidc.IsClientAllowedFunc, opts ...TokenRevocationOption) Option {
	return func(p *Provider) error {
		p.config.TokenRevocationEnabled = true
		p.config.TokenRevocationIsClientAllowedFunc = f
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithTokenRevocationRevokeGrantOnAccessToken makes access token revocation
// revoke the underlying grant instead of revoking only the presented access
// token. For JWT access tokens, this is required for revocation to have any
// effect, since JWTs are not stored server-side.
func WithTokenRevocationRevokeGrantOnAccessToken() TokenRevocationOption {
	return func(p *Provider) error {
		p.config.TokenRevocationRevokeGrantOnAccessTokenEnabled = true
		return nil
	}
}

// WithTokenRevocationEndpoint overrides the default value for the token
// revocation endpoint which is [defaultEndpointTokenRevocation].
func WithTokenRevocationEndpoint(endpoint string) TokenRevocationOption {
	return func(p *Provider) error {
		p.config.TokenRevocationEndpoint = endpoint
		return nil
	}
}

// ── MTLS ──────────────────────────────────────────────────────────────────────

// MTLSOption is an optional configuration for mutual TLS.
// See [WithMTLS] for more information.
type MTLSOption Option

// MTLSConfig holds the required configuration for mutual TLS support.
type MTLSConfig struct {
	// Host is the mTLS-specific host the provider listens on. Client
	// certificate-authenticated requests must be routed to this host.
	Host string
	// ClientCertFunc extracts the client certificate from the request.
	ClientCertFunc goidc.ClientCertFunc
}

// WithMTLS allows requests to be established with mutual TLS.
func WithMTLS(cfg MTLSConfig, opts ...MTLSOption) Option {
	return func(p *Provider) error {
		if cfg.Host == "" {
			return errors.New("the mtls host cannot be empty")
		}
		if cfg.ClientCertFunc == nil {
			return errors.New("the mtls client certificate function cannot be nil")
		}
		p.config.MTLSEnabled = true
		p.config.MTLSHost = cfg.Host
		p.config.ClientCertFunc = cfg.ClientCertFunc
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithMTLSTokenBinding makes requests to /token return tokens bound to the
// client certificate if any is sent.
func WithMTLSTokenBinding() MTLSOption {
	return func(p *Provider) error {
		p.config.MTLSTokenBindingEnabled = true
		return nil
	}
}

// WithMTLSTokenBindingRequired makes requests to /token return tokens bound to the
// client certificate.
func WithMTLSTokenBindingRequired() MTLSOption {
	return func(p *Provider) error {
		p.config.MTLSTokenBindingEnabled = true
		p.config.MTLSTokenBindingRequired = true
		return nil
	}
}

// ── DPoP ──────────────────────────────────────────────────────────────────────

// DPoPOption is an optional configuration for DPoP.
// See [WithDPoP] for more information.
type DPoPOption Option

// WithDPoP enables proof of possession with DPoP.
// It requires tokens to be bound to a cryptographic key generated by the client.
// By default, the max difference between the claims "iat" and "exp" of DPoP JWTs is set to [defaultJWTLifetimeSecs].
func WithDPoP(sigAlgs []goidc.SignatureAlgorithm, opts ...DPoPOption) Option {
	return func(p *Provider) error {
		if len(sigAlgs) == 0 {
			return errors.New("at least one signature algorithm is required for DPoP")
		}
		if slices.Contains(sigAlgs, goidc.None) {
			return errors.New("'none' algorithm is not allowed for DPoP")
		}
		p.config.DPoPEnabled = true
		p.config.DPoPSigAlgs = sigAlgs
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithDPoPRequired makes DPoP required.
func WithDPoPRequired() DPoPOption {
	return func(p *Provider) error {
		p.config.DPoPRequired = true
		return nil
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required in order to issue an access token to a client.
// For more info, see [WithMTLSTokenBinding] and [WithDPoP].
func WithTokenBindingRequired() Option {
	return func(p *Provider) error {
		p.config.TokenBindingRequired = true
		return nil
	}
}

// ── Resource Indicators ───────────────────────────────────────────────────────

// ResourceIndicatorOption is an optional configuration for Resource Indicators.
// See [WithResourceIndicators] for more information.
type ResourceIndicatorOption Option

// WithResourceIndicators enables client to indicate which resources they intend
// to access.
func WithResourceIndicators(resources []goidc.ResourceIndicator, opts ...ResourceIndicatorOption) Option {
	return func(p *Provider) error {
		p.config.ResourceIndicatorsEnabled = true
		p.config.ResourceIndicators = resources
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithResourceIndicatorsRequired makes resource indicators required.
func WithResourceIndicatorsRequired() ResourceIndicatorOption {
	return func(p *Provider) error {
		p.config.ResourceIndicatorsRequired = true
		return nil
	}
}

// ── RAR ───────────────────────────────────────────────────────────────────────

// RAROption is an optional configuration for Rich Authorization Requests.
// See [WithRAR] for more information.
type RAROption Option

// WithRAR enables Rich Authorization Requests (RFC 9396).
func WithRAR(types []goidc.AuthDetailType, opts ...RAROption) Option {
	return func(p *Provider) error {
		if len(types) == 0 {
			return errors.New("at least one authorization detail type is required for RAR")
		}
		p.config.RAREnabled = true
		p.config.RARDetailTypes = types
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithRARDetailValidator sets the function used to validate authorization detail
// objects.
func WithRARDetailValidator(f goidc.RARValidateDetailFunc) RAROption {
	return func(p *Provider) error {
		p.config.RARValidateDetailFunc = f
		return nil
	}
}

// WithRARDetailsComparator sets the function used to validate that the
// authorization details requested during authorization_code or refresh_token
// grants are consistent with the originally granted ones.
func WithRARDetailsComparator(f goidc.RARCompareDetailsFunc) RAROption {
	return func(p *Provider) error {
		p.config.RARCompareDetailsFunc = f
		return nil
	}
}

// ── Misc ──────────────────────────────────────────────────────────────────────

// WithLocalhostRedirectURIs allows clients to use localhost redirect URIs,
// which are otherwise rejected by default.
func WithLocalhostRedirectURIs() Option {
	return func(p *Provider) error {
		p.config.LocalhostRedirectURIEnabled = true
		return nil
	}
}

// WithACRs makes available authentication context references.
// These values will be published as are in the openid configuration endpoint response.
func WithACRs(values ...goidc.ACR) Option {
	return func(p *Provider) error {
		if len(values) == 0 {
			return errors.New("at least one ACR value is required")
		}
		p.config.ACRs = values
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the
// authorization endpoint.
// These values will be published as are in the openid configuration endpoint response.
func WithDisplayValues(values ...goidc.DisplayValue) Option {
	return func(p *Provider) error {
		if len(values) == 0 {
			return errors.New("at least one display value is required")
		}
		p.config.DisplayValues = values
		return nil
	}
}

// WithStaticClients adds static clients to the provider.
// The static clients are kept in memory only and are checked before consulting
// the client manager.
func WithStaticClients(cs ...*goidc.Client) Option {
	return func(p *Provider) error {
		if len(cs) == 0 {
			return errors.New("at least one client is required")
		}
		p.config.StaticClients = cs
		return nil
	}
}

// ── OpenID Federation ─────────────────────────────────────────────────────────

// OpenIDFedOption is an optional configuration for OpenID Federation.
// See [WithOpenIDFederation] for more information.
type OpenIDFedOption Option

// OpenIDFedConfig holds the required configuration for OpenID Federation support.
type OpenIDFedConfig struct {
	// Manager is the storage used to persist federated clients.
	// If nil, the default in-memory storage is used.
	Manager goidc.OpenIDFedManager
	// JWKSFunc returns the provider's federation JWKS, used to sign the
	// provider's entity configuration. This JWKS is separate from the
	// provider's regular signing keys. See [WithSigner] if the private keys
	// are not available.
	JWKSFunc goidc.JWKSFunc
	// SigAlg is the algorithm used to sign the entity configuration.
	// The JWKSFunc must return a key matching this algorithm.
	SigAlg goidc.SignatureAlgorithm
	// AuthorityHints are entity identifiers of immediate superiors that can
	// issue subordinate statements about this provider, helping relying
	// parties discover trust paths to a trusted anchor.
	AuthorityHints []string
	// TrustedAnchors are trust anchor entity IDs that the provider accepts
	// when resolving trust chains for federated clients.
	TrustedAnchors []string
}

// WithOpenIDFederation enables OpenID Federation support, allowing the provider
// to participate in a trust federation where trust relationships are established
// through signed entity statements rather than pre-configured client registrations.
//
// [OpenID Federation specification]: https://openid.net/specs/openid-federation-1_0.html.
func WithOpenIDFederation(cfg OpenIDFedConfig, opts ...OpenIDFedOption) Option {
	return func(p *Provider) error {
		if cfg.JWKSFunc == nil {
			return errors.New("the federation jwks function cannot be nil")
		}
		if cfg.SigAlg == "" {
			return errors.New("a federation signature algorithm must be provided")
		}
		if len(cfg.AuthorityHints) == 0 {
			return errors.New("at least one authority hint is required")
		}
		if len(cfg.TrustedAnchors) == 0 {
			return errors.New("at least one trusted anchor is required")
		}
		p.config.OpenIDFedEnabled = true
		p.config.OpenIDFedManager = cfg.Manager
		p.config.OpenIDFedJWKSFunc = cfg.JWKSFunc
		p.config.OpenIDFedSigAlg = cfg.SigAlg
		p.config.OpenIDFedAuthorityHints = cfg.AuthorityHints
		p.config.OpenIDFedTrustedAnchors = cfg.TrustedAnchors
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithOpenIDFedClientRegistrationTypes sets the client registration types available for the OpenID Federation.
func WithOpenIDFedClientRegistrationTypes(types ...goidc.ClientRegistrationType) OpenIDFedOption {
	return func(p *Provider) error {
		if len(types) == 0 {
			return errors.New("at least one client registration type is required")
		}
		p.config.OpenIDFedClientRegTypes = types
		return nil
	}
}

// WithOpenIDFedSignatureAlgs sets the signature algorithms accepted to parse entity statements and trust marks.
// If not set, defaults to [OpenIDFedConfig.SigAlg].
func WithOpenIDFedSignatureAlgs(algs ...goidc.SignatureAlgorithm) OpenIDFedOption {
	return func(p *Provider) error {
		if len(algs) == 0 {
			return errors.New("at least one signature algorithm is required")
		}
		p.config.OpenIDFedSigAlgs = algs
		return nil
	}
}

// WithOpenIDFedSigner sets a custom signing function.
func WithOpenIDFedSigner(f goidc.SignerFunc) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedSignerFunc = f
		return nil
	}
}

// WithOpenIDFedRequiredClientTrustMarks sets a custom function to determine the required trust marks.
func WithOpenIDFedRequiredClientTrustMarks(f goidc.RequiredTrustMarksFunc) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedRequiredClientTrustMarksFunc = f
		return nil
	}
}

// WithOpenIDFedRegistrationEndpoint sets the registration endpoint for the OpenID Federation.
func WithOpenIDFedRegistrationEndpoint(endpoint string) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedRegistrationEndpoint = endpoint
		return nil
	}
}

// WithOpenIDFedTrustChainMaxDepth sets the maximum depth of the trust chain.
func WithOpenIDFedTrustChainMaxDepth(depth int) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedTrustChainMaxDepth = depth
		return nil
	}
}

// WithOpenIDFedJWKSRepresentations sets the JWKS representations available for the Federation OpenID Provider.
// For more information, see [OpenID Fed §5.2.1].
func WithOpenIDFedJWKSRepresentations(reps ...goidc.JWKSRepresentation) OpenIDFedOption {
	return func(p *Provider) error {
		if len(reps) == 0 {
			return errors.New("at least one JWKS representation is required")
		}
		p.config.OpenIDFedJWKSRepresentations = reps
		return nil
	}
}

// WithOpenIDFedSignedJWKSEndpoint sets the endpoint path for the signed JWKS.
// The signed JWKS is a JWT-wrapped representation of the provider's JWKS,
// providing integrity protection. This is used when [goidc.OpenIDFedJWKSRepresentationSignedURI]
// is enabled via [WithOpenIDFedJWKSRepresentations].
func WithOpenIDFedSignedJWKSEndpoint(endpoint string) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedSignedJWKSEndpoint = endpoint
		return nil
	}
}

// WithOpenIDFedSignedJWKSLifetimeSecs sets the lifetime in seconds for signed JWKS JWTs.
// After this duration, the signed JWKS expires and must be re-fetched.
// If set to 0, the signed JWKS will not include an expiration claim.
func WithOpenIDFedSignedJWKSLifetimeSecs(secs int) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedSignedJWKSLifetimeSecs = secs
		return nil
	}
}

// WithOpenIDFedOrganizationName sets the human-readable organization name
// that appears in the provider's entity configuration metadata.
func WithOpenIDFedOrganizationName(name string) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedOrganizationName = name
		return nil
	}
}

// WithOpenIDFedHTTPClient sets a custom HTTP client function for federation operations.
// This allows customization of HTTP requests made when fetching entity configurations,
// subordinate statements, and trust marks from other federation entities.
func WithOpenIDFedHTTPClient(f goidc.HTTPClientFunc) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedHTTPClientFunc = f
		return nil
	}
}

// WithOpenIDFedClientHandler sets a custom function to handle the client during federation registration.
func WithOpenIDFedClientHandler(f goidc.HandleClientFunc) OpenIDFedOption {
	return func(p *Provider) error {
		p.config.OpenIDFedHandleClientFunc = f
		return nil
	}
}

// WithOpenIDFedTrustMarks configures trust marks that the provider will fetch and include
// in its entity configuration. Trust marks are credentials issued by accreditation
// authorities that attest to certain properties of the provider.
func WithOpenIDFedTrustMarks(configs ...goidc.TrustMarkConfig) OpenIDFedOption {
	return func(p *Provider) error {
		if len(configs) == 0 {
			return errors.New("trust mark configurations is empty")
		}
		p.config.OpenIDFedTrustMarkConfigs = configs
		return nil
	}
}

// ── SSF ───────────────────────────────────────────────────────────────────────

// SSFOption is an optional configuration for the Shared Signals Framework.
// See [WithSSF] for more information.
type SSFOption Option

// SSFConfig holds the required configuration for Shared Signals Framework support.
type SSFConfig struct {
	// Manager is responsible for persisting event stream configurations created
	// by receivers. If nil, the default in-memory storage is used.
	Manager goidc.SSFEventStreamManager
	// JWKSFunc returns the provider's SSF JWKS, used to sign Security Event
	// Tokens (SETs). This JWKS is separate from the provider's regular signing keys.
	// See [WithSigner] if the private keys are not available.
	JWKSFunc goidc.JWKSFunc
	// SigAlg is the algorithm used to sign SETs.
	// The JWKSFunc must return a key matching this algorithm.
	SigAlg goidc.SignatureAlgorithm
	// ReceiverFunc authenticates incoming requests and returns the SSF receiver
	// (relying party) information. Called on every SSF API request.
	ReceiverFunc goidc.SSFAuthenticatedReceiverFunc
	// EventTypes are the security event types supported by this SSF transmitter.
	EventTypes []goidc.SSFEventType
}

// WithSSF enables the Shared Signals Framework (SSF) support, allowing the provider
// to act as an SSF transmitter that publishes security events to receivers (relying parties).
// SSF enables real-time sharing of security-related signals such as session revocation,
// credential changes, and other CAEP (Continuous Access Evaluation Protocol) events.
//
// [OpenID Shared Signals Framework specification]: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
func WithSSF(cfg SSFConfig, opts ...SSFOption) Option {
	return func(p *Provider) error {
		if cfg.JWKSFunc == nil {
			return errors.New("the ssf jwks function cannot be nil")
		}
		if cfg.SigAlg == "" {
			return errors.New("a ssf signature algorithm must be provided")
		}
		if cfg.ReceiverFunc == nil {
			return errors.New("the ssf receiver function cannot be nil")
		}
		if len(cfg.EventTypes) == 0 {
			return errors.New("at least one ssf event type must be provided")
		}
		p.config.SSFEnabled = true
		p.config.SSFEventStreamManager = cfg.Manager
		p.config.SSFJWKSFunc = cfg.JWKSFunc
		p.config.SSFDefaultSigAlg = cfg.SigAlg
		p.config.SSFAuthenticatedReceiverFunc = cfg.ReceiverFunc
		p.config.SSFEventTypes = cfg.EventTypes
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithSSFPollDelivery enables the poll delivery method, where receivers poll the
// transmitter for events. The manager is responsible for queuing events and
// tracking acknowledgements.
func WithSSFPollDelivery(manager goidc.SSFEventPollManager) SSFOption {
	return func(p *Provider) error {
		p.config.SSFDeliveryMethods = append(p.config.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll)
		p.config.SSFEventPollManager = manager
		return nil
	}
}

// WithSSFPushDelivery enables the push delivery method, where the transmitter
// pushes events to receiver endpoints.
func WithSSFPushDelivery(httpClientFunc goidc.HTTPClientFunc) SSFOption {
	return func(p *Provider) error {
		p.config.SSFDeliveryMethods = append(p.config.SSFDeliveryMethods, goidc.SSFDeliveryMethodPush)
		p.config.SSFHTTPClientFunc = httpClientFunc
		return nil
	}
}

// WithSSFEventStreamStatusManagement enables the stream status management API,
// allowing receivers to read and update the status of their event streams
// (e.g., enabled, paused, disabled).
func WithSSFEventStreamStatusManagement() SSFOption {
	return func(p *Provider) error {
		p.config.SSFIsStatusManagementEnabled = true
		return nil
	}
}

// WithSSFEventStreamSubjectManagement enables the subject management API,
// allowing receivers to add or remove specific subjects they want to receive
// events for on a given stream.
func WithSSFEventStreamSubjectManagement() SSFOption {
	return func(p *Provider) error {
		p.config.SSFIsSubjectManagementEnabled = true
		return nil
	}
}

// WithSSFStatusEndpoint overrides the default endpoint for stream status management.
func WithSSFStatusEndpoint(endpoint string) SSFOption {
	return func(p *Provider) error {
		p.config.SSFStatusEndpoint = endpoint
		return nil
	}
}

// WithSSFAddSubjectEndpoint overrides the default endpoint for adding subjects to a stream.
func WithSSFAddSubjectEndpoint(endpoint string) SSFOption {
	return func(p *Provider) error {
		p.config.SSFAddSubjectEndpoint = endpoint
		return nil
	}
}

// WithSSFRemoveSubjectEndpoint overrides the default endpoint for removing subjects from a stream.
func WithSSFRemoveSubjectEndpoint(endpoint string) SSFOption {
	return func(p *Provider) error {
		p.config.SSFRemoveSubjectEndpoint = endpoint
		return nil
	}
}

// WithSSFEventStreamVerification enables the verification API, allowing receivers
// to request verification events to confirm the stream is working correctly.
// The transmitter responds by sending a verification event with an optional state value.
// If the function is nil, the provider will use the default in memory verification implementation.
func WithSSFEventStreamVerification(f goidc.SSFScheduleVerificationEventFunc) SSFOption {
	return func(p *Provider) error {
		p.config.SSFIsVerificationEnabled = true
		p.config.SSFScheduleVerificationEventFunc = f
		return nil
	}
}

// WithSSFMinVerificationInterval sets the minimum interval (in seconds) between
// verification requests from the same receiver. This prevents abuse of the verification endpoint.
func WithSSFMinVerificationInterval(secs int) SSFOption {
	return func(p *Provider) error {
		p.config.SSFMinVerificationInterval = secs
		return nil
	}
}

// WithSSFDefaultSubjects indicates how subjects are handled when a stream is created.
// Use [goidc.SSFDefaultSubjectAll] when automatically including all subjects by default, or
// [goidc.SSFDefaultSubjectNone] when requiring explicit subject registration via the subject management API.
func WithSSFDefaultSubjects(defaultSubjects goidc.SSFDefaultSubject) SSFOption {
	return func(p *Provider) error {
		p.config.SSFDefaultSubjects = defaultSubjects
		return nil
	}
}

// WithSSFCriticalSubjectMembers sets the subject identifier members that must be processed by the receiver.
func WithSSFCriticalSubjectMembers(subs ...string) SSFOption {
	return func(p *Provider) error {
		if len(subs) == 0 {
			return errors.New("at least one critical subject member is required")
		}
		p.config.SSFCriticalSubjectMembers = subs
		return nil
	}
}

// WithSSFAuthorizationSchemes sets the authorization schemes published in the SSF
// configuration endpoint. This informs receivers how to authenticate when calling
// the SSF APIs (e.g., Bearer tokens, OAuth 2.0).
func WithSSFAuthorizationSchemes(schemes ...goidc.SSFAuthorizationScheme) SSFOption {
	return func(p *Provider) error {
		if len(schemes) == 0 {
			return errors.New("at least one authorization scheme is required")
		}
		p.config.SSFAuthorizationSchemes = schemes
		return nil
	}
}

// WithSSFInactivityTimeout sets the inactivity timeout for event streams.
// [SSF 1.0 §8.1.1] If a stream has no activity for this duration, the handleFunc
// is called to handle the expired stream (e.g., pause or delete it).
func WithSSFInactivityTimeout(secs int, handleFunc goidc.SSFHandleExpiredEventStreamFunc) SSFOption {
	return func(p *Provider) error {
		p.config.SSFInactivityTimeoutSecs = secs
		p.config.SSFHandleExpiredEventStreamFunc = handleFunc
		return nil
	}
}

// WithSSFMultipleStreamsPerReceiver controls whether a single receiver
// can create multiple event streams.
func WithSSFMultipleStreamsPerReceiver() SSFOption {
	return func(p *Provider) error {
		p.config.SSFMultipleStreamsPerReceiverEnabled = true
		return nil
	}
}

// ── Logout ────────────────────────────────────────────────────────────────────

// LogoutOption is an option for [WithLogout].
type LogoutOption Option

// WithLogout enables the [OpenID Connect RP-initiated logout flow](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
// The manager stores pending logout sessions while the flow is in progress. If
// manager is nil, the default in-memory storage is used.
// The default logout function is used when the flow is completed and the client
// does not provide a post_logout_redirect_uri. Use [WithLogoutPolicies] to
// configure which logout flows will be executed. The default logout session
// timeout is [defaultLogoutSessionTimeoutSecs].
// LogoutConfig holds the required configuration for logout support.
type LogoutConfig struct {
	// Manager persists logout sessions. If nil, the default in-memory
	// storage is used.
	Manager goidc.LogoutManager
	// HandleFunc is called when the logout flow completes and the client did
	// not provide a post_logout_redirect_uri.
	HandleFunc goidc.HandleDefaultPostLogoutFunc
}

func WithLogout(cfg LogoutConfig, opts ...LogoutOption) Option {
	return func(p *Provider) error {
		p.config.LogoutEnabled = true
		p.config.LogoutManager = cfg.Manager
		p.config.HandleDefaultPostLogoutFunc = cfg.HandleFunc
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithLogoutPolicies configures the logout policies that are evaluated for each
// RP-initiated logout request. The first policy whose setup function matches is
// used to execute the logout flow.
func WithLogoutPolicies(logoutPolicies ...goidc.LogoutPolicy) LogoutOption {
	return func(p *Provider) error {
		p.config.LogoutPolicies = logoutPolicies
		return nil
	}
}

// WithLogoutSessionTimeoutSecs sets the logout session timeout.
func WithLogoutSessionTimeoutSecs(secs int) LogoutOption {
	return func(p *Provider) error {
		p.config.LogoutSessionTimeoutSecs = secs
		return nil
	}
}

// WithLogoutEndpoint sets the logout endpoint.
func WithLogoutEndpoint(endpoint string) LogoutOption {
	return func(p *Provider) error {
		p.config.LogoutEndpoint = endpoint
		return nil
	}
}

// WithLogoutSessionIDFunc sets the function to generate logout session IDs.
func WithLogoutSessionIDFunc(f goidc.RandomFunc) LogoutOption {
	return func(p *Provider) error {
		p.config.LogoutSessionIDFunc = f
		return nil
	}
}

// ── Verifiable Credentials ────────────────────────────────────────────────────

// VCIOption is an option for [WithVCI].
type VCIOption Option

// WithVCI enables Verifiable Credential issuance support,
// registering the credential issuers available at this provider.
func WithVCI(opts ...VCIOption) Option {
	return func(p *Provider) error {
		p.config.VCIEnabled = true
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithVCIIssuerState enables issuer state support. The handler resolves the
// credential configuration IDs associated with issuer_state.
func WithVCIIssuerState(handler goidc.VCIIssuerStateHandleFunc) VCIOption {
	return func(p *Provider) error {
		if handler == nil {
			return errors.New("issuer state handler is required")
		}
		p.config.VCIIssuerStateEnabled = true
		p.config.VCIIssuerStateHandleFunc = handler
		return nil
	}
}

type VCISelfOption VCIOption

type VCISelfConfig struct {
	Issuer string
}

func WithVCISelf(configs map[goidc.VCConfigurationID]goidc.VCConfiguration, opts ...VCISelfOption) VCIOption {
	return func(p *Provider) error {
		p.config.VCISelfEnabled = true
		p.config.VCISelfConfigurations = configs
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

func WithVCISelfIssuer(iss string) VCISelfOption {
	return func(p *Provider) error {
		p.config.VCISelfHost = iss
		return nil
	}
}

// WithVCISelfOffers enables credential offers for the self credential issuer.
func WithVCISelfOffers(manager goidc.VCOfferManager) VCISelfOption {
	return func(p *Provider) error {
		p.config.VCISelfOffersEnabled = true
		p.config.VCISelfOfferManager = manager
		return nil
	}
}

// WithVCISelfPreAuthCodeGrant enables the pre-authorized code grant for the
// self credential issuer. If manager is nil, the default in-memory manager is
// used.
func WithVCISelfPreAuthCodeGrant(manager goidc.VCPreAuthCodeGrantManager) VCISelfOption {
	return func(p *Provider) error {
		if !slices.Contains(p.config.GrantTypes, goidc.GrantPreAuthorizedCode) {
			p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantPreAuthorizedCode)
		}
		p.config.VCISelfPreAuthCodeGrantEnabled = true
		p.config.VCISelfPreAuthCodeGrantManager = manager
		return nil
	}
}

// WithVCISelfPreAuthCodeFunc sets the function used to generate
// pre-authorized codes.
func WithVCISelfPreAuthCodeFunc(f goidc.RandomFunc) VCISelfOption {
	return func(p *Provider) error {
		p.config.VCISelfPreAuthCodeFunc = f
		return nil
	}
}

// WithVCISelfPreAuthCodeLifetime sets the pre-authorized code lifetime in
// seconds.
func WithVCISelfPreAuthCodeLifetime(secs int) VCISelfOption {
	return func(p *Provider) error {
		p.config.VCISelfPreAuthCodeLifetimeSecs = secs
		return nil
	}
}

type VCISelfJWTIssuerOption VCISelfOption

func WithVCISelfJWTIssuer(opts ...VCISelfJWTIssuerOption) VCISelfOption {
	return func(p *Provider) error {
		p.config.VCISelfJWTIssuerEnabled = true
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

func WithVCISelfJWTIssuerJWKS(jwks goidc.JWKSFunc) VCISelfJWTIssuerOption {
	return func(p *Provider) error {
		p.config.VCISelfJWTIssuerJWKSFunc = jwks
		return nil
	}
}

func WithVCISelfJWTIssuerJWKSURI(uri string) VCISelfJWTIssuerOption {
	return func(p *Provider) error {
		p.config.VCISelfJWTIssuerJWKSURI = uri
		return nil
	}
}

// VCIExternalOption is an option for [WithVCIExternal].
type VCIExternalOption Option

// WithVCIExternal registers external credential issuers.
func WithVCIExternal(issuers []goidc.VCIssuer, opts ...VCIExternalOption) VCIOption {
	return func(p *Provider) error {
		p.config.VCIIssuers = append(p.config.VCIIssuers, issuers...)
		for _, opt := range opts {
			if err := opt(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithVCIExternalPreAuthCodeGrant enables the pre-authorized code grant for
// external credential issuers. The handler validates and consumes the code and
// returns its authorized issuance context.
func WithVCIExternalPreAuthCodeGrant(handler goidc.VCIPreAuthCodeHandleFunc) VCIExternalOption {
	return func(p *Provider) error {
		if handler == nil {
			return errors.New("pre-auth code handler is required")
		}
		if !slices.Contains(p.config.GrantTypes, goidc.GrantPreAuthorizedCode) {
			p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantPreAuthorizedCode)
		}
		p.config.VCIExternalPreAuthCodeGrantEnabled = true
		p.config.VCIExternalPreAuthCodeHandleFunc = handler
		return nil
	}
}
