package provider

// TODO: Review defaults, params and validations.

import (
	"errors"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *provider) error

// WithStorage defines how the provider will store clients and sessions.
// It overrides the default storage which keeps everything in memory.
func WithStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) ProviderOption {
	return func(p *provider) error {
		p.config.Storage.Client = clientManager
		p.config.Storage.AuthnSession = authnSessionManager
		p.config.Storage.GrantSession = grantSessionManager
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
		p.config.Endpoint.Prefix = prefix
		return nil
	}
}

// WithJWKSEndpoint overrides the default value for the jwks endpoint which is
// /jwks.
func WithJWKSEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.JWKS = endpoint
		return nil
	}
}

// WithTokenEndpoint overrides the default value for the authorization
// endpoint which is /token.
func WithTokenEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.Token = endpoint
		return nil
	}
}

// WithAuthorizeEndpoint overrides the default value for the token endpoint
// which is /authorize.
func WithAuthorizeEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.Authorize = endpoint
		return nil
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is /par.
func WithPAREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.PushedAuthorization = endpoint
		return nil
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is /register.
func WithDCREndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.DCR = endpoint
		return nil
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is /userinfo.
func WithUserInfoEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.UserInfo = endpoint
		return nil
	}
}

// WithIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is /introspect.
func WithIntrospectionEndpoint(endpoint string) ProviderOption {
	return func(p *provider) error {
		p.config.Endpoint.Introspection = endpoint
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
func WithUserInfoSignatureKeyIDs(defaultSignatureKeyID string, signatureKeyIDs ...string) ProviderOption {
	return func(p *provider) error {
		if !slices.Contains(signatureKeyIDs, defaultSignatureKeyID) {
			signatureKeyIDs = append(
				signatureKeyIDs,
				defaultSignatureKeyID,
			)
		}
		p.config.User.SigKeyIDs = signatureKeyIDs
		return nil
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// The default is 600 seconds.
func WithIDTokenLifetime(idTokenLifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.User.IDTokenLifetimeSecs = idTokenLifetimeSecs
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
		p.config.User.EncIsEnabled = true
		p.config.User.KeyEncAlgs = keyEncAlgs
		p.config.User.DefaultContentEncAlg = jose.A128CBC_HS256
		p.config.User.ContentEncAlg = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithDCR allows clients to be registered dynamically.
// The plugin is executed during registration and update of the client to
// perform custom validations (e.g. validate a custom property) or set default
// values (e.g. set the default scopes).
func WithDCR(
	plugin goidc.DCRFunc,
	rotateTokens bool,
) ProviderOption {
	return func(p *provider) error {
		p.config.DCR.IsEnabled = true
		p.config.DCR.Plugin = plugin
		p.config.DCR.TokenRotationIsEnabled = rotateTokens
		return nil
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// If true, rotateTokens causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenGrant(
	refreshTokenLifetimeSecs int,
	rotateTokens bool,
) ProviderOption {
	return func(p *provider) error {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		p.config.RefreshToken.LifetimeSecs = refreshTokenLifetimeSecs
		p.config.RefreshToken.RotationIsEnabled = rotateTokens
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
		p.config.TokenOptions = func(
			c *goidc.Client,
			scopes string,
		) (
			goidc.TokenOptions,
			error,
		) {
			opts, err := tokenOpts(c, scopes)
			if err != nil {
				return goidc.TokenOptions{}, err
			}

			// Opaque access tokens cannot be the same size of refresh tokens.
			if opts.OpaqueLength == token.RefreshTokenLength {
				opts.OpaqueLength++
			}

			if !slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) {
				opts.IsRefreshable = false
			}

			return opts, nil
		}
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
func WithPAR(parLifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.PAR.IsEnabled = true
		p.config.PAR.LifetimeSecs = parLifetimeSecs
		return nil
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
func WithPARRequired(parLifetimeSecs int) ProviderOption {
	return func(p *provider) error {
		p.config.PAR.IsRequired = true
		return WithPAR(parLifetimeSecs)(p)
	}
}

// WithUnregisteredRedirectURIsDuringPAR allows clients to inform unregistered
// redirect URIs during request to pushed authorization endpoint.
// This only takes effect when PAR is enabled
func WithUnregisteredRedirectURIsDuringPAR() ProviderOption {
	return func(p *provider) error {
		p.config.PAR.AllowUnregisteredRedirectURI = true
		return nil
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
func WithJAR(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.JAR.IsEnabled = true
		p.config.JAR.LifetimeSecs = jarLifetimeSecs
		for _, jarAlgorithm := range jarAlgorithms {
			p.config.JAR.SigAlgs = append(
				p.config.JAR.SigAlgs,
				jose.SignatureAlgorithm(jarAlgorithm),
			)
		}
		return nil
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
func WithJARRequired(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.JAR.IsRequired = true
		return WithJAR(jarLifetimeSecs, jarAlgorithms...)(p)
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
// The default content encryption algorithm is A128CBC-HS256.
func WithJAREncryption(
	// TODO: Use the first key as the default
	keyEncryptionIDs []string,
) ProviderOption {
	return func(p *provider) error {
		p.config.JAR.EncIsEnabled = true
		p.config.JAR.KeyEncIDs = keyEncryptionIDs
		p.config.JAR.DefaultContentEncAlg = jose.A128CBC_HS256
		p.config.JAR.ContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// It enables JWT response modes.
func WithJARM(
	jarmLifetimeSecs int,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) ProviderOption {
	return func(p *provider) error {
		if !slices.Contains(jarmSignatureKeyIDs, defaultJARMSignatureKeyID) {
			jarmSignatureKeyIDs = append(jarmSignatureKeyIDs, defaultJARMSignatureKeyID)
		}

		p.config.JARM.IsEnabled = true
		p.config.ResponseModes = append(
			p.config.ResponseModes,
			goidc.ResponseModeJWT,
			goidc.ResponseModeQueryJWT,
			goidc.ResponseModeFragmentJWT,
			goidc.ResponseModeFormPostJWT,
		)
		p.config.JARM.LifetimeSecs = jarmLifetimeSecs
		p.config.JARM.DefaultSigKeyID = defaultJARMSignatureKeyID
		p.config.JARM.SigKeyIDs = jarmSignatureKeyIDs
		return nil
	}
}

// WithJARM allows responses for authorization requests to be sent as encrypted
// JWTs.
// If none passed, the default key encryption is RSA-OAEP-256.
// The default content encryption algorithm is A128CBC-HS256.
func WithJARMEncryption(
	keyEncAlgs ...jose.KeyAlgorithm,
) ProviderOption {
	if len(keyEncAlgs) == 0 {
		keyEncAlgs = append(keyEncAlgs, jose.RSA_OAEP_256)
	}

	return func(p *provider) error {
		p.config.JARM.EncIsEnabled = true
		p.config.JARM.KeyEncAlgs = keyEncAlgs
		p.config.JARM.DefaultContentEncAlg = jose.A128CBC_HS256
		p.config.JARM.ContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256}
		return nil
	}
}

// WithBasicSecretAuthn allows secret basic client authentication.
func WithBasicSecretAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
		return nil
	}
}

// WithSecretPostAuthn allows secret post client authentication.
func WithSecretPostAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
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
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnPrivateKeyJWT,
		)
		p.config.ClientAuthn.PrivateKeyJWTSigAlgs = sigAlgs
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
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
		p.config.ClientAuthn.ClientSecretJWTSigAlgs = sigAlgs
		return nil
	}
}

// assertionLifetimeSecs defines a maximum threshold for the difference between
// issuance and expiry time of client assertions.
// signatureAlgorithms defines the symmetric algorithms allowed to sign the
// assertions.
func WithAssertionLifetime(secs int) ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.AssertionLifetimeSecs = secs
		return nil
	}
}

// WithTLSAuthn allows tls client authentication.
func WithTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnTLS,
		)
		return nil
	}
}

// WithSelfSignedTLSAuthn allows self signed tls client authentication.
func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSelfSignedTLS,
		)
		return nil
	}
}

// WithNoneAuthn allows none client authentication.
func WithNoneAuthn() ProviderOption {
	return func(p *provider) error {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
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

		p.config.AuthDetails.IsEnabled = true
		p.config.AuthDetails.Types = types
		return nil
	}
}

// WithMTLS allows requests to be established with mutual TLS.
// If clientCertFunc is not nil, it will be used to extract the client
// certificate from the request. The default logic is to extract the client
// certificate from the header [goidc.HeaderClientCertificate].
func WithMTLS(
	mtlsHost string,
	bindTokens bool,
	clientCertFunc goidc.ClientCertFunc,
) ProviderOption {
	return func(p *provider) error {
		p.config.MTLS.IsEnabled = true
		p.config.MTLS.Host = mtlsHost
		p.config.MTLS.ClientCertFunc = clientCertFunc
		p.config.MTLS.TokenBindingIsEnabled = bindTokens
		return nil
	}
}

// WithDPoP enables proof of possesion with DPoP.
// It requires tokens to be bound to a cryptographic key generated by the client.
// If not algorithm is informed, the default is RS256.
func WithDPoP(
	lifetimeSecs int,
	signingAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	if len(signingAlgs) == 0 {
		signingAlgs = append(signingAlgs, jose.RS256)
	}
	return func(p *provider) error {
		p.config.DPoP.IsEnabled = true
		p.config.DPoP.LifetimeSecs = lifetimeSecs
		for _, signatureAlgorithm := range signingAlgs {
			p.config.DPoP.SigAlgs = append(
				p.config.DPoP.SigAlgs,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
		return nil
	}
}

// WithDPoPRequired makes DPoP required.
// For more information, see [WithDPoP].
func WithDPoPRequired(
	lifetimeSecs int,
	signingAlgs ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *provider) error {
		p.config.DPoP.IsRequired = true
		return WithDPoP(lifetimeSecs, signingAlgs...)(p)
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required, in order to issue an access token to a client.
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
		p.config.Introspection.IsEnabled = true
		p.config.Introspection.ClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantIntrospection)
		return nil
	}
}

// WithPKCE makes proof key for code exchange available to clients.
// The first code challenged informed is used as the default.
// If no code challenge method is informed, the default is S256.
func WithPKCE(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	if len(codeChallengeMethods) == 0 {
		codeChallengeMethods = append(codeChallengeMethods, goidc.CodeChallengeMethodSHA256)
	}
	return func(p *provider) error {
		p.config.PKCE.IsEnabled = true
		p.config.PKCE.DefaultChallengeMethod = codeChallengeMethods[0]
		p.config.PKCE.ChallengeMethods = codeChallengeMethods
		return nil
	}
}

// WithPKCERequired makes proof key for code exchange required.
// For more info, see [WithPKCE].
func WithPKCERequired(
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *provider) error {
		p.config.PKCE.IsRequired = true
		return WithPKCE(codeChallengeMethods...)(p)
	}
}

// WithACRs makes available authentication context references.
// These values will be published as are.
func WithACRs(
	acrValues ...goidc.ACR,
) ProviderOption {
	return func(p *provider) error {
		p.config.ACRs = acrValues
		return nil
	}
}

// WithDisplayValues makes available display values during requests to the authorization
// endpoint.
// These values will be published as are.
func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *provider) error {
		p.config.DisplayValues = values
		return nil
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
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
// This will also change some of the behavior of the server during runtime to be
// compliant with the FAPI 2.0.
func WithProfileFAPI2() ProviderOption {
	return func(p *provider) error {
		p.config.Profile = goidc.ProfileFAPI2
		return nil
	}
}

// WithStaticClient adds a static client to the provider.
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
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithAuthorizeErrorPlugin(plugin goidc.AuthorizeErrorFunc) ProviderOption {
	return func(p *provider) error {
		p.config.AuthorizeErrPlugin = plugin
		return nil
	}
}

func WithResourceIndicators(resources ...string) ProviderOption {
	return func(p *provider) error {
		if len(resources) == 0 {
			return errors.New("at least one resource indicator must be provided")
		}
		p.config.ResourceIndicators.IsEnabled = true
		p.config.ResourceIndicators.Resources = resources
		return nil
	}
}

func WithResourceIndicatorsRequired(resources ...string) ProviderOption {
	return func(p *provider) error {
		p.config.ResourceIndicators.IsRequired = true
		return WithResourceIndicators(resources...)(p)
	}
}

// WithOutterAuthorizationParamsRequired requires that the required
// authorization params be informed as query parameters during requests to the
// authorization endpoint even if they were informed previously during PAR
// or inside JAR.
// This option is mandatory for the OpenID profile.
func WithOutterAuthorizationParamsRequired() ProviderOption {
	return func(p *provider) error {
		p.config.OutterAuthParamsRequired = true
		return nil
	}
}