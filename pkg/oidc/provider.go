package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type TlsOptions struct {
	TlsAddress        string
	ServerCertificate string
	ServerKey         string
	CipherSuites      []uint16
	// The fields below will be used only if mtls is enalbed.
	MtlsAddress                    string
	CaCertificatePool              *x509.CertPool
	UnsecureCertificatesAreAllowed bool
}

type OpenIdProvider struct {
	config utils.Configuration
}

func NewProvider(
	host string,
	clientManager crud.ClientManager,
	authnSessionManager crud.AuthnSessionManager,
	grantSessionManager crud.GrantSessionManager,
	privateJwks jose.JSONWebKeySet,
	defaultTokenKeyId string,
	defaultIdTokenKeyId string,
) *OpenIdProvider {
	provider := &OpenIdProvider{
		config: utils.Configuration{
			Host:                host,
			Profile:             constants.OpenIdProfile,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			Scopes:              []string{string(constants.OpenIdScope)},
			GetTokenOptions: func(client models.Client, scopes string) (models.TokenOptions, error) {
				return models.TokenOptions{
					TokenExpiresInSecs: constants.DefaultTokenLifetimeSecs,
					TokenFormat:        constants.JwtTokenFormat,
				}, nil
			},
			PrivateJwks:                   privateJwks,
			DefaultTokenSignatureKeyId:    defaultTokenKeyId,
			DefaultUserInfoSignatureKeyId: defaultIdTokenKeyId,
			UserInfoSignatureKeyIds:       []string{defaultIdTokenKeyId},
			IdTokenExpiresInSecs:          600,
			UserClaims:                    []string{},
			GrantTypes: []constants.GrantType{
				constants.AuthorizationCodeGrant,
			},
			ResponseTypes: []constants.ResponseType{constants.CodeResponse},
			ResponseModes: []constants.ResponseMode{
				constants.QueryResponseMode,
				constants.FragmentResponseMode,
				constants.FormPostResponseMode,
			},
			ClientAuthnMethods:               []constants.ClientAuthnType{},
			DpopSignatureAlgorithms:          []jose.SignatureAlgorithm{},
			SubjectIdentifierTypes:           []constants.SubjectIdentifierType{constants.PublicSubjectIdentifier},
			ClaimTypes:                       []constants.ClaimType{constants.NormalClaimType},
			AuthenticationSessionTimeoutSecs: constants.DefaultAuthenticationSessionTimeoutSecs,
			CorrelationIdHeader:              constants.CorrelationIdHeader,
		},
	}

	return provider
}

// TODO: Add more validations.
func (provider *OpenIdProvider) validateConfiguration() error {
	for _, keyId := range slices.Concat(
		[]string{provider.config.DefaultUserInfoSignatureKeyId},
		provider.config.UserInfoSignatureKeyIds,
		provider.config.JarmSignatureKeyIds,
	) {
		if len(provider.config.PrivateJwks.Key(keyId)) == 0 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS", keyId)
		}
	}

	for _, signatureAlgorithm := range provider.config.PrivateKeyJwtSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	for _, signatureAlgorithm := range provider.config.ClientSecretJwtSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	if provider.config.IntrospectionIsEnabled && (!unit.ContainsAll(provider.config.ClientAuthnMethods, provider.config.IntrospectionClientAuthnMethods...) ||
		slices.Contains(provider.config.IntrospectionClientAuthnMethods, constants.NoneAuthn)) {
		return errors.New("invalid client authentication method for token introspection")
	}

	if provider.config.UserInfoEncryptionIsEnabled && !slices.Contains(provider.config.UserInfoContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm") // todo
	}

	if provider.config.Profile == constants.OpenIdProfile {
		defaultIdTokenSignatureKey := provider.config.PrivateJwks.Key(provider.config.DefaultUserInfoSignatureKeyId)[0]
		if defaultIdTokenSignatureKey.Algorithm != string(jose.RS256) {
			return errors.New("the default signature algorithm for ID tokens must be RS256")
		}

		defaultJarmSignatureKey := provider.config.PrivateJwks.Key(provider.config.DefaultJarmSignatureKeyId)[0]
		if defaultJarmSignatureKey.Algorithm != string(jose.RS256) {
			return errors.New("the default signature algorithm for JARM must be RS256")
		}
	}

	if provider.config.Profile == constants.Fapi2Profile {

		if slices.ContainsFunc(provider.config.ClientAuthnMethods, func(authnMethod constants.ClientAuthnType) bool {
			// TODO: remove self signed, only for tests.
			return authnMethod != constants.PrivateKeyJwtAuthn && authnMethod != constants.TlsAuthn && authnMethod != constants.SelfSignedTlsAuthn
		}) {
			return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
		}

		if slices.Contains(provider.config.GrantTypes, constants.ImplicitGrant) {
			return errors.New("the implict grant is not allowed for FAPI 2.0")
		}

		if !provider.config.ParIsEnabled || !provider.config.ParIsRequired {
			return errors.New("pushed authorization requests is required for FAPI 2.0")
		}

		if !provider.config.PkceIsEnabled || !provider.config.PkceIsRequired {
			return errors.New("proof key for code exchange is required for FAPI 2.0")
		}

		if !provider.config.IssuerResponseParameterIsEnabled {
			return errors.New("the issuer response parameter is required for FAPI 2.0")
		}
	}

	return nil
}

func (provider *OpenIdProvider) SetSupportedUserClaims(claims ...string) {
	provider.config.UserClaims = claims
}

func (provider *OpenIdProvider) AddIdTokenSignatureKeyIds(idTokenSignatureKeyIds ...string) {
	if !unit.ContainsAll(idTokenSignatureKeyIds, provider.config.DefaultUserInfoSignatureKeyId) {
		idTokenSignatureKeyIds = append(idTokenSignatureKeyIds, provider.config.DefaultUserInfoSignatureKeyId)
	}
	provider.config.UserInfoSignatureKeyIds = idTokenSignatureKeyIds
}

func (provider *OpenIdProvider) SetIdTokenLifetime(idTokenLifetimeSecs int) {
	provider.config.IdTokenExpiresInSecs = idTokenLifetimeSecs
}

func (provider *OpenIdProvider) EnableIdTokenEncryption(
	keyEncryptionAlgorithms []jose.KeyAlgorithm,
	contentEncryptionAlgorithms []jose.ContentEncryption,
) {
	provider.config.UserInfoEncryptionIsEnabled = true
	provider.config.UserInfoKeyEncryptionAlgorithms = keyEncryptionAlgorithms
	provider.config.UserInfoContentEncryptionAlgorithms = contentEncryptionAlgorithms
}

func (provider *OpenIdProvider) EnableDynamicClientRegistration(dcrPlugin utils.DcrPluginFunc, shouldRotateTokens bool) {
	provider.config.DcrIsEnabled = true
	provider.config.DcrPlugin = dcrPlugin
	provider.config.ShouldRotateRegistrationTokens = shouldRotateTokens

}

func (provider *OpenIdProvider) EnableRefreshTokenGrantType(refreshTokenLifetimeSecs int, shouldRotateTokens bool) {
	provider.config.GrantTypes = append(provider.config.GrantTypes, constants.RefreshTokenGrant)
	provider.config.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	provider.config.ShouldRotateRefreshTokens = shouldRotateTokens
}

func (provider *OpenIdProvider) RequireOpenIdScope() {
	provider.config.OpenIdScopeIsRequired = true
}

func (provider *OpenIdProvider) SetTokenOptions(getTokenOpts utils.GetTokenOptionsFunc) {
	provider.config.GetTokenOptions = getTokenOpts
}

func (provider *OpenIdProvider) EnableImplicitGrantType() {
	provider.config.GrantTypes = append(provider.config.GrantTypes, constants.ImplicitGrant)
	provider.config.ResponseTypes = append(
		provider.config.ResponseTypes,
		constants.TokenResponse,
		constants.IdTokenResponse,
		constants.IdTokenAndTokenResponse,
		constants.CodeAndIdTokenResponse,
		constants.CodeAndTokenResponse,
		constants.CodeAndIdTokenAndTokenResponse,
	)
}

func (provider *OpenIdProvider) SetScopes(scopes ...string) {
	if slices.Contains(scopes, string(constants.OpenIdScope)) {
		provider.config.Scopes = scopes
	} else {
		provider.config.Scopes = append(scopes, string(constants.OpenIdScope))
	}
}

func (provider *OpenIdProvider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.config.ParLifetimeSecs = parLifetimeSecs
	provider.config.ParIsEnabled = true
}

func (provider *OpenIdProvider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.EnablePushedAuthorizationRequests(parLifetimeSecs)
	provider.config.ParIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.config.JarIsEnabled = true
	provider.config.JarLifetimeSecs = jarLifetimeSecs
	provider.config.JarSignatureAlgorithms = jarAlgorithms
}

func (provider *OpenIdProvider) RequireJwtSecuredAuthorizationRequests(
	jarLifetimeSecs int,
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableJwtSecuredAuthorizationRequests(jarLifetimeSecs, jarAlgorithms...)
	provider.config.JarIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJarmSignatureKeyId string,
	jarmSignatureKeyIds ...string,
) {
	if !unit.ContainsAll(jarmSignatureKeyIds, defaultJarmSignatureKeyId) {
		jarmSignatureKeyIds = append(jarmSignatureKeyIds, defaultJarmSignatureKeyId)
	}

	provider.config.JarmIsEnabled = true
	provider.config.ResponseModes = append(
		provider.config.ResponseModes,
		constants.JwtResponseMode,
		constants.QueryJwtResponseMode,
		constants.FragmentJwtResponseMode,
		constants.FormPostJwtResponseMode,
	)
	provider.config.JarmLifetimeSecs = jarmLifetimeSecs
	provider.config.DefaultJarmSignatureKeyId = defaultJarmSignatureKeyId
	provider.config.JarmSignatureKeyIds = jarmSignatureKeyIds

}

func (provider *OpenIdProvider) EnableBasicSecretClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.ClientSecretBasicAuthn)
}

func (provider *OpenIdProvider) EnableSecretPostClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.ClientSecretPostAuthn)
}

func (provider *OpenIdProvider) EnablePrivateKeyJwtClientAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.PrivateKeyJwtAuthn)
	provider.config.PrivateKeyJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.config.PrivateKeyJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableClientSecretJwtAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.ClientSecretBasicAuthn)
	provider.config.ClientSecretJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.config.ClientSecretJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableTlsClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.TlsAuthn)
}

func (provider *OpenIdProvider) EnableSelfSignedTlsClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.SelfSignedTlsAuthn)
}

func (provider *OpenIdProvider) EnableMtls(mtlsHost string) {
	provider.config.MtlsIsEnabled = true
	provider.config.MtlsHost = mtlsHost
}

func (provider *OpenIdProvider) EnableTlsBoundTokens() {
	provider.config.TlsBoundTokensIsEnabled = true
}

func (provider *OpenIdProvider) EnableNoneClientAuthn() {
	provider.config.ClientAuthnMethods = append(provider.config.ClientAuthnMethods, constants.NoneAuthn)
}

func (provider *OpenIdProvider) EnableIssuerResponseParameter() {
	provider.config.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableClaimsParameter() {
	provider.config.ClaimsParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.config.DpopIsEnabled = true
	provider.config.DpopLifetimeSecs = dpopLifetimeSecs
	provider.config.DpopSignatureAlgorithms = dpopSigningAlgorithms
}

func (provider *OpenIdProvider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	provider.config.DpopIsRequired = true
}

func (provider *OpenIdProvider) RequireSenderConstrainedTokens() {
	provider.config.SenderConstrainedTokenIsRequired = true
}

func (provider *OpenIdProvider) EnableTokenIntrospection(clientAuthnMethods ...constants.ClientAuthnType) {
	provider.config.IntrospectionIsEnabled = true
	provider.config.IntrospectionClientAuthnMethods = clientAuthnMethods
	provider.config.GrantTypes = append(provider.config.GrantTypes, constants.IntrospectionGrant)
}

func (provider *OpenIdProvider) EnableProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.config.CodeChallengeMethods = codeChallengeMethods
	provider.config.PkceIsEnabled = true
}

func (provider *OpenIdProvider) RequireProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	provider.config.PkceIsRequired = true
}

func (provider *OpenIdProvider) SetSupportedAuthenticationContextReferences(
	acrValues ...constants.AuthenticationContextReference,
) {
	provider.config.AuthenticationContextReferences = acrValues
}

func (provider *OpenIdProvider) SetDisplayValuesSupported(values ...constants.DisplayValue) {
	provider.config.DisplayValues = values
}

func (provider *OpenIdProvider) SetClaimTypesSupported(types ...constants.ClaimType) {
	provider.config.ClaimTypes = types
}

func (provider *OpenIdProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.config.AuthenticationSessionTimeoutSecs = timeoutSecs
}

func (provider *OpenIdProvider) SetCorrelationIdHeader(header string) {
	provider.config.CorrelationIdHeader = header
}

func (provider *OpenIdProvider) SetFapi2Profile() {
	provider.config.Profile = constants.Fapi2Profile
}

func (provider *OpenIdProvider) AddClient(client models.Client) error {
	return provider.config.ClientManager.Create(client)
}

func (provider *OpenIdProvider) AddPolicy(policy utils.AuthnPolicy) {
	provider.config.Policies = append(provider.config.Policies, policy)
}

func (provider *OpenIdProvider) Run(address string) error {
	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	handler := provider.getServerHandler()
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	return http.ListenAndServe(address, handler)
}

func (provider *OpenIdProvider) RunTls(config TlsOptions) error {

	if err := provider.validateConfiguration(); err != nil {
		return err
	}

	if provider.config.MtlsIsEnabled {
		go provider.runMtls(config)
	}

	handler := provider.getServerHandler()
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	server := &http.Server{
		Addr:    config.TlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIdProvider) runMtls(config TlsOptions) error {

	handler := provider.getMtlsServerHandler()
	handler = apihandlers.NewAddCorrelationIdHeaderMiddlewareHandler(handler, provider.config.CorrelationIdHeader)
	handler = apihandlers.NewAddCacheControlHeadersMiddlewareHandler(handler)
	handler = apihandlers.NewAddCertificateHeaderMiddlewareHandler(handler)

	tlsClientAuthnType := tls.RequireAndVerifyClientCert
	if config.CaCertificatePool == nil || config.UnsecureCertificatesAreAllowed {
		tlsClientAuthnType = tls.RequireAnyClientCert
	}

	server := &http.Server{
		Addr:    config.MtlsAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			ClientCAs:    config.CaCertificatePool,
			ClientAuth:   tlsClientAuthnType,
			CipherSuites: config.CipherSuites,
		},
	}
	return server.ListenAndServeTLS(config.ServerCertificate, config.ServerKey)
}

func (provider *OpenIdProvider) getServerHandler() http.Handler {

	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"GET "+string(constants.JsonWebKeySetEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleJWKSRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	serverHandler.HandleFunc(
		"GET "+string(constants.AuthorizationEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.AuthorizationEndpoint)+"/{callback}",
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleAuthorizeCallbackRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.WellKnownEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleWellKnownRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.DcrIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.DynamicClientEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientCreation(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"PUT "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientUpdate(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"GET "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientRetrieve(utils.NewContext(provider.config, r, w))
			},
		)

		serverHandler.HandleFunc(
			"DELETE "+string(constants.DynamicClientEndpoint)+"/{client_id}",
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleDynamicClientDelete(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}

func (provider *OpenIdProvider) getMtlsServerHandler() http.Handler {
	serverHandler := http.NewServeMux()

	serverHandler.HandleFunc(
		"POST "+string(constants.TokenEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleTokenRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"GET "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	serverHandler.HandleFunc(
		"POST "+string(constants.UserInfoEndpoint),
		func(w http.ResponseWriter, r *http.Request) {
			apihandlers.HandleUserInfoRequest(utils.NewContext(provider.config, r, w))
		},
	)

	if provider.config.ParIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.PushedAuthorizationRequestEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleParRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	if provider.config.IntrospectionIsEnabled {
		serverHandler.HandleFunc(
			"POST "+string(constants.TokenIntrospectionEndpoint),
			func(w http.ResponseWriter, r *http.Request) {
				apihandlers.HandleIntrospectionRequest(utils.NewContext(provider.config, r, w))
			},
		)
	}

	return serverHandler
}
