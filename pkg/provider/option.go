package provider

import (
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ProviderOption func(p *Provider)

// WithStorage defines how the provider will store clients and sessions.
// It overrides the default storage which keeps everything in memory.
func WithStorage(
	clientManager goidc.ClientManager,
	authnSessionManager goidc.AuthnSessionManager,
	grantSessionManager goidc.GrantSessionManager,
) ProviderOption {
	return func(p *Provider) {
		p.config.Storage.Client = clientManager
		p.config.Storage.AuthnSession = authnSessionManager
		p.config.Storage.GrantSession = grantSessionManager
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
	return func(p *Provider) {
		p.config.Endpoint.Prefix = prefix
	}
}

// WithJWKSEndpoint overrides the default value for the jwks endpoint which is
// /jwks.
func WithJWKSEndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.JWKS = endpoint
	}
}

// WithTokenEndpoint overrides the default value for the authorization
// endpoint which is /token.
func WithTokenEndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.Token = endpoint
	}
}

// WithAuthorizeEndpoint overrides the default value for the token endpoint
// which is /authorize.
func WithAuthorizeEndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.Authorize = endpoint
	}
}

// WithPAREndpoint overrides the default value for the par endpoint which
// is /par.
func WithPAREndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.PushedAuthorization = endpoint
	}
}

// WithDCREndpoint overrides the default value for the dcr endpoint which
// is /register.
func WithDCREndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.DCR = endpoint
	}
}

// WithUserInfoEndpoint overrides the default value for the user info endpoint
// which is /userinfo.
func WithUserInfoEndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.UserInfo = endpoint
	}
}

// WithIntrospectionEndpoint overrides the default value for the introspection
// endpoint which is /introspect.
func WithIntrospectionEndpoint(endpoint string) ProviderOption {
	return func(p *Provider) {
		p.config.Endpoint.Introspection = endpoint
	}
}

// WithClaims signals support for custom user claims.
// These claims are meant to appear in ID tokens and the userinfo endpoint.
// The values provided will be shared with the field "claims_supported" of the
// well known endpoint response.
// The default value for "claim_types_supported" is set to "normal".
func WithClaims(claims ...string) ProviderOption {
	return func(p *Provider) {
		p.config.Claims = claims
		p.config.ClaimTypes = []goidc.ClaimType{goidc.ClaimTypeNormal}
	}
}

// WithClaimTypes defines the types supported for the user claims.
// The value provided are published at "claim_types_supported".
func WithClaimTypes(types ...goidc.ClaimType) ProviderOption {
	return func(p *Provider) {
		p.config.ClaimTypes = types
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
	return func(p *Provider) {
		if !slices.Contains(signatureKeyIDs, defaultSignatureKeyID) {
			signatureKeyIDs = append(
				signatureKeyIDs,
				defaultSignatureKeyID,
			)
		}
		p.config.User.SignatureKeyIDs = signatureKeyIDs
	}
}

// WithIDTokenLifetime overrides the default ID token lifetime.
// The default is 600 seconds.
func WithIDTokenLifetime(idTokenLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.User.IDTokenExpiresInSecs = idTokenLifetimeSecs
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

	return func(p *Provider) {
		p.config.User.EncryptionIsEnabled = true
		p.config.User.KeyEncryptionAlgorithms = keyEncAlgs
		p.config.User.DefaultContentEncryptionAlgorithm = jose.A128CBC_HS256
		p.config.User.ContentEncryptionAlgorithms = []jose.ContentEncryption{jose.A128CBC_HS256}
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
	return func(p *Provider) {
		p.config.DCR.IsEnabled = true
		p.config.DCR.Plugin = plugin
		p.config.DCR.TokenRotationIsEnabled = rotateTokens
	}
}

// WithRefreshTokenGrant makes available the refresh token grant.
// If true, rotateTokens causes a new refresh token to be issued each time
// one is used. The one used during the request then becomes invalid.
func WithRefreshTokenGrant(
	refreshTokenLifetimeSecs int64,
	rotateTokens bool,
) ProviderOption {
	return func(p *Provider) {
		p.config.GrantTypes = append(p.config.GrantTypes, goidc.GrantRefreshToken)
		p.config.RefreshToken.LifetimeSecs = refreshTokenLifetimeSecs
		p.config.RefreshToken.RotationIsEnabled = rotateTokens
	}
}

// WithOpenIDScopeRequired forces the openid scope to be informed in all requests.
func WithOpenIDScopeRequired() ProviderOption {
	return func(p *Provider) {
		p.config.OpenIDIsRequired = true
	}
}

// WithTokenOptions defines how access tokens are issued.
func WithTokenOptions(tokenOpts goidc.TokenOptionsFunc) ProviderOption {
	return func(p *Provider) {
		p.config.TokenOptions = func(
			client *goidc.Client,
			scopes string,
		) (
			goidc.TokenOptions,
			error,
		) {
			opts, err := tokenOpts(client, scopes)
			if err != nil {
				return goidc.TokenOptions{}, err
			}

			if opts.OpaqueLength == token.RefreshTokenLength {
				opts.OpaqueLength++
			}

			if !client.IsGrantTypeAllowed(goidc.GrantRefreshToken) {
				opts.IsRefreshable = false
			}

			return opts, nil
		}
	}
}

// WithImplicitGrant allows the implicit grant type and the associated
// response types.
func WithImplicitGrant() ProviderOption {
	return func(p *Provider) {
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
	}
}

// WithScopes defines the scopes accepted by the provider.
// Since the scope openid is required, it will be added in case scopes doesn't
// contain it.
func WithScopes(scopes ...goidc.Scope) ProviderOption {
	return func(p *Provider) {
		p.config.Scopes = scopes
		// The scope openid is required to be among the scopes.
		for _, scope := range scopes {
			if scope.ID == goidc.ScopeOpenID.ID {
				return
			}
		}
		p.config.Scopes = append(scopes, goidc.ScopeOpenID)
	}
}

// WithPAR allows authorization flows to start at the pushed authorization
// request endpoint.
func WithPAR(parLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.PAR.IsEnabled = true
		p.config.PAR.LifetimeSecs = parLifetimeSecs
	}
}

// WithPARRequired forces authorization flows to start at the pushed
// authorization request endpoint.
func WithPARRequired(parLifetimeSecs int64) ProviderOption {
	return func(p *Provider) {
		WithPAR(parLifetimeSecs)(p)
		p.config.PAR.IsRequired = true
	}
}

// WithUnregisteredRedirectURIsDuringPAR allows clients to inform unregistered
// redirect URIs during request to pushed authorization endpoint.
// This only takes effect when PAR is enabled
func WithUnregisteredRedirectURIsDuringPAR() ProviderOption {
	return func(p *Provider) {
		p.config.PAR.AllowUnregisteredRedirectURI = true
	}
}

// WithJAR allows authorization requests to be securely sent as signed JWTs.
func WithJAR(
	jarLifetimeSecs int64,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.JAR.IsEnabled = true
		p.config.JAR.LifetimeSecs = jarLifetimeSecs
		for _, jarAlgorithm := range jarAlgorithms {
			p.config.JAR.SignatureAlgorithms = append(
				p.config.JAR.SignatureAlgorithms,
				jose.SignatureAlgorithm(jarAlgorithm),
			)
		}
	}
}

// WithJARRequired requires authorization requests to be securely sent as
// signed JWTs.
func WithJARRequired(
	jarLifetimeSecs int64,
	jarAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithJAR(jarLifetimeSecs, jarAlgorithms...)(p)
		p.config.JAR.IsRequired = true
	}
}

// WithJAREncryption allows authorization requests to be securely sent as
// encrypted JWTs.
// The default content encryption algorithm is A128CBC-HS256.
func WithJAREncryption(
	// TODO: Use the first key as the default
	keyEncryptionIDs []string,
) ProviderOption {
	return func(p *Provider) {
		p.config.JAR.EncryptionIsEnabled = true
		p.config.JAR.KeyEncryptionIDs = keyEncryptionIDs
		p.config.JAR.DefaultContentEncryptionAlgorithm = jose.A128CBC_HS256
		p.config.JAR.ContentEncryptionAlgorithms = []jose.ContentEncryption{jose.A128CBC_HS256}
	}
}

// WithJARM allows responses for authorization requests to be sent as signed JWTs.
// It enables JWT response modes.
func WithJARM(
	jarmLifetimeSecs int64,
	defaultJARMSignatureKeyID string,
	jarmSignatureKeyIDs ...string,
) ProviderOption {
	return func(p *Provider) {
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
		p.config.JARM.DefaultSignatureKeyID = defaultJARMSignatureKeyID
		p.config.JARM.SignatureKeyIDs = jarmSignatureKeyIDs
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

	return func(p *Provider) {
		p.config.JARM.EncryptionIsEnabled = true
		p.config.JARM.KeyEncrytionAlgorithms = keyEncAlgs
		p.config.JARM.DefaultContentEncryptionAlgorithm = jose.A128CBC_HS256
		p.config.JARM.ContentEncryptionAlgorithms = []jose.ContentEncryption{jose.A128CBC_HS256}
	}
}

// WithBasicSecretAuthn allows secret basic client authentication.
func WithBasicSecretAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
	}
}

// WithSecretPostAuthn allows secret post client authentication.
func WithSecretPostAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretPost,
		)
	}
}

// WithPrivateKeyJWTAuthn allows private key jwt client authentication.
// assertionLifetimeSecs defines a maximum threshold for the difference between
// issuance and expiry time of client assertions.
// signatureAlgorithms defines the symmetric algorithms allowed to sign the
// assertions.
func WithPrivateKeyJWTAuthn(
	assertionLifetimeSecs int64,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnPrivateKeyJWT,
		)
		p.config.ClientAuthn.PrivateKeyJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.ClientAuthn.PrivateKeyJWTSignatureAlgorithms = append(
				p.config.ClientAuthn.PrivateKeyJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithBasicSecretAuthn allows client secret jwt client authentication.
// assertionLifetimeSecs defines a maximum threshold for the difference between
// issuance and expiry time of client assertions.
// signatureAlgorithms defines the symmetric algorithms allowed to sign the
// assertions.
func WithClientSecretJWTAuthn(
	assertionLifetimeSecs int64,
	signatureAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSecretBasic,
		)
		p.config.ClientAuthn.ClientSecretJWTAssertionLifetimeSecs = assertionLifetimeSecs
		for _, signatureAlgorithm := range signatureAlgorithms {
			p.config.ClientAuthn.ClientSecretJWTSignatureAlgorithms = append(
				p.config.ClientAuthn.ClientSecretJWTSignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithTLSAuthn allows tls client authentication.
func WithTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnTLS,
		)
	}
}

// WithSelfSignedTLSAuthn allows self signed tls client authentication.
func WithSelfSignedTLSAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnSelfSignedTLS,
		)
	}
}

// WithNoneAuthn allows none client authentication.
func WithNoneAuthn() ProviderOption {
	return func(p *Provider) {
		p.config.ClientAuthn.Methods = append(
			p.config.ClientAuthn.Methods,
			goidc.ClientAuthnNone,
		)
	}
}

// WithIssuerResponseParameter enables the "iss" parameter to be sent in the
// response of authorization requests.
func WithIssuerResponseParameter() ProviderOption {
	return func(p *Provider) {
		p.config.IssuerResponseParameterIsEnabled = true
	}
}

// WithClaimsParameter allows clients to send the "claims" parameter during
// authorization requests.
func WithClaimsParameter() ProviderOption {
	return func(p *Provider) {
		p.config.ClaimsParameterIsEnabled = true
	}
}

// WithAuthorizationDetails allows clients to make rich authorization requests.
func WithAuthorizationDetails(types ...string) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizationDetails.IsEnabled = true
		p.config.AuthorizationDetails.Types = types
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
	return func(p *Provider) {
		p.config.MTLS.IsEnabled = true
		p.config.MTLS.Host = mtlsHost
		p.config.MTLS.ClientCertFunc = clientCertFunc
		p.config.MTLS.TokenBindingIsEnabled = bindTokens
	}
}

// WithDPoP enables demonstrating proof of possesion which allows tokens to be
// bound to a cryptographic key.
func WithDPoP(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		p.config.DPoP.IsEnabled = true
		p.config.DPoP.LifetimeSecs = dpopLifetimeSecs
		for _, signatureAlgorithm := range dpopSigningAlgorithms {
			p.config.DPoP.SignatureAlgorithms = append(
				p.config.DPoP.SignatureAlgorithms,
				jose.SignatureAlgorithm(signatureAlgorithm),
			)
		}
	}
}

// WithDPoP requires tokens to be bound to a cryptographic key by demonstrating
// proof of possesion.
func WithDPoPRequired(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) ProviderOption {
	return func(p *Provider) {
		WithDPoP(dpopLifetimeSecs, dpopSigningAlgorithms...)(p)
		p.config.DPoP.IsRequired = true
	}
}

// WithTokenBindingRequired makes at least one sender constraining mechanism
// (TLS or DPoP) be required, in order to issue an access token to a client.
func WithTokenBindingRequired() ProviderOption {
	return func(p *Provider) {
		p.config.TokenBindingIsRequired = true
	}
}

// WithIntrospection allows authorized clients to introspect tokens.
func WithIntrospection(
	clientAuthnMethods ...goidc.ClientAuthnType,
) ProviderOption {
	return func(p *Provider) {
		p.config.Introspection.IsEnabled = true
		p.config.Introspection.ClientAuthnMethods = clientAuthnMethods
		p.config.GrantTypes = append(
			p.config.GrantTypes,
			goidc.GrantIntrospection,
		)
	}
}

// WithPKCE makes proof key for code exchange available to clients.
func WithPKCE(
	defaultCodeChallengeMethod goidc.CodeChallengeMethod,
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {

	if !slices.Contains(codeChallengeMethods, defaultCodeChallengeMethod) {
		codeChallengeMethods = append(codeChallengeMethods, defaultCodeChallengeMethod)
	}
	return func(p *Provider) {
		p.config.PKCE.IsEnabled = true
		p.config.PKCE.DefaultCodeChallengeMethod = defaultCodeChallengeMethod
		p.config.PKCE.CodeChallengeMethods = codeChallengeMethods
	}
}

// WithPKCERequired makes proof key for code exchange required.
func WithPKCERequired(
	defaultCodeChallengeMethod goidc.CodeChallengeMethod,
	codeChallengeMethods ...goidc.CodeChallengeMethod,
) ProviderOption {
	return func(p *Provider) {
		WithPKCE(defaultCodeChallengeMethod, codeChallengeMethods...)(p)
		p.config.PKCE.IsRequired = true
	}
}

// WithACRs makes available authentication context references.
// These values will be published as are.
func WithACRs(
	acrValues ...goidc.ACR,
) ProviderOption {
	return func(p *Provider) {
		p.config.ACRs = acrValues
	}
}

// WithACRs makes available display values during requests to the authorization
// endpoint.
// These values will be published as are.
func WithDisplayValues(values ...goidc.DisplayValue) ProviderOption {
	return func(p *Provider) {
		p.config.DisplayValues = values
	}
}

// WithAuthenticationSessionTimeout sets the user authentication session lifetime.
// This defines how long an authorization request may last.
func WithAuthenticationSessionTimeout(timeoutSecs int64) ProviderOption {
	return func(p *Provider) {
		p.config.AuthnSessionTimeoutSecs = timeoutSecs
	}
}

// WithProfileFAPI2 defines the OpenID Provider profile as FAPI 2.0.
// The server will only be able to run if it is configured respecting the
// FAPI 2.0 profile.
// This will also change some of the behavior of the server during runtime to be
// compliant with the FAPI 2.0.
func WithProfileFAPI2() ProviderOption {
	return func(p *Provider) {
		p.config.Profile = goidc.ProfileFAPI2
	}
}

// WithStaticClient adds a static client to the provider.
// The static clients are checked before consulting the client manager.
func WithStaticClient(client *goidc.Client) ProviderOption {
	return func(p *Provider) {
		p.config.StaticClients = append(p.config.StaticClients, client)
	}
}

// WithPolicy adds an authentication policy that will be evaluated at runtime
// and then executed if selected.
func WithPolicy(policy goidc.AuthnPolicy) ProviderOption {
	return func(p *Provider) {
		p.config.Policies = append(p.config.Policies, policy)
	}
}

// WithAuthorizeErrorPlugin defines a handler to be executed when the
// authorization request results in error, but the error can't be redirected.
// This can be used to display a page with the error.
// The default behavior is to display a JSON with the error information to the user.
func WithAuthorizeErrorPlugin(plugin goidc.AuthorizeErrorFunc) ProviderOption {
	return func(p *Provider) {
		p.config.AuthorizeErrorPlugin = plugin
	}
}

func WithResourceIndicators(resources []string) ProviderOption {
	return func(p *Provider) {
		p.config.ResourceIndicators.IsEnabled = true
		p.config.ResourceIndicators.Resources = resources
	}
}

func WithResourceIndicatorsRequired(resources []string) ProviderOption {
	return func(p *Provider) {
		WithResourceIndicators(resources)
		p.config.ResourceIndicators.IsRequired = true
	}
}

// WithOutterAuthorizationParamsRequired requires that the required
// authorization params be informed as query parameters during requests to the
// authorization endpoint even if they were informed previously during PAR
// or inside JAR.
// This option is mandatory for the OpenID profile.
func WithOutterAuthorizationParamsRequired() ProviderOption {
	return func(p *Provider) {
		p.config.OutterAuthParamsRequired = true
	}
}
