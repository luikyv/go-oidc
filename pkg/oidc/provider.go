package oidc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OpenIdProvider struct {
	utils.Configuration
	Server *gin.Engine
}

func NewProvider(
	host string,
	clientManager crud.ClientManager,
	authnSessionManager crud.AuthnSessionManager,
	grantSessionManager crud.GrantSessionManager,
	privateJwks jose.JSONWebKeySet,
	defaultTokenKeyId string,
	defaultIdTokenKeyId string,
	templates string,
) *OpenIdProvider {
	provider := &OpenIdProvider{
		Configuration: utils.Configuration{
			Host:                host,
			Profile:             constants.OpenIdProfile,
			ClientManager:       clientManager,
			AuthnSessionManager: authnSessionManager,
			GrantSessionManager: grantSessionManager,
			Scopes:              []string{constants.OpenIdScope},
			GetTokenOptions: func(client models.Client, scopes string) models.TokenOptions {
				return models.TokenOptions{
					TokenExpiresInSecs: constants.DefaultTokenLifetimeSecs,
					TokenFormat:        constants.JwtTokenFormat,
				}
			},
			PrivateJwks:                  privateJwks,
			DefaultTokenSignatureKeyId:   defaultTokenKeyId,
			DefaultIdTokenSignatureKeyId: defaultIdTokenKeyId,
			IdTokenSignatureKeyIds:       []string{defaultIdTokenKeyId},
			IdTokenExpiresInSecs:         600,
			CustomIdTokenClaims:          []constants.Claim{},
			GrantTypes: []constants.GrantType{
				constants.ClientCredentialsGrant,
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
			AuthenticationSessionTimeoutSecs: constants.DefaultAuthenticationSessionTimeoutSecs,
		},
		Server: gin.Default(),
	}
	provider.Server.LoadHTMLGlob(templates)

	return provider
}

func (provider *OpenIdProvider) validateConfiguration() {

	defaultIdTokenSignatureKey := provider.PrivateJwks.Key(provider.DefaultIdTokenSignatureKeyId)[0]
	if provider.Profile == constants.OpenIdProfile && defaultIdTokenSignatureKey.Algorithm != string(jose.RS256) {
		panic("the default signature algorithm for ID tokens must be RS256")
	}

	defaultJarmSignatureKey := provider.PrivateJwks.Key(provider.DefaultJarmSignatureKeyId)[0]
	if provider.Profile == constants.OpenIdProfile && defaultJarmSignatureKey.Algorithm != string(jose.RS256) {
		panic("the default signature algorithm for JARM must be RS256")
	}

	for _, signatureAlgorithm := range provider.PrivateKeyJwtSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			panic("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	for _, signatureAlgorithm := range provider.ClientSecretJwtSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			panic("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}
}

func (provider *OpenIdProvider) SetCustomIdTokenClaims(claims ...constants.Claim) {
	provider.CustomIdTokenClaims = claims
}

func (provider *OpenIdProvider) AddIdTokenSignatureKeyIds(idTokenSignatureKeyIds ...string) {
	if !unit.ContainsAll(idTokenSignatureKeyIds, provider.DefaultIdTokenSignatureKeyId) {
		idTokenSignatureKeyIds = append(idTokenSignatureKeyIds, provider.DefaultIdTokenSignatureKeyId)
	}
	provider.IdTokenSignatureKeyIds = idTokenSignatureKeyIds
}

func (provider *OpenIdProvider) SetIdTokenLifetime(idTokenLifetimeSecs int) {
	provider.IdTokenExpiresInSecs = idTokenLifetimeSecs
}

func (provider *OpenIdProvider) EnableDynamicClientRegistration(dcrPlugin utils.DcrPluginFunc, shouldRotateTokens bool) {
	provider.DcrIsEnabled = true
	provider.DcrPlugin = dcrPlugin
	provider.ShouldRotateRegistrationTokens = shouldRotateTokens

}

func (provider *OpenIdProvider) EnableRefreshTokenGrantType(refreshTokenLifetimeSecs int, shouldRotateTokens bool) {
	provider.GrantTypes = append(provider.GrantTypes, constants.RefreshTokenGrant)
	provider.RefreshTokenLifetimeSecs = refreshTokenLifetimeSecs
	provider.ShouldRotateRefreshTokens = shouldRotateTokens
}

func (provider *OpenIdProvider) RequireOpenIdScope() {
	provider.OpenIdScopeIsRequired = true
}

func (provider *OpenIdProvider) SetTokenOptions(getTokenOpts utils.GetTokenOptionsFunc) {
	provider.GetTokenOptions = getTokenOpts
}

func (provider *OpenIdProvider) EnableImplicitGrantType() {
	provider.GrantTypes = append(provider.GrantTypes, constants.ImplicitGrant)
	provider.ResponseTypes = append(
		provider.ResponseTypes,
		constants.TokenResponse,
		constants.IdTokenResponse,
		constants.IdTokenAndTokenResponse,
		constants.CodeAndIdTokenResponse,
		constants.CodeAndTokenResponse,
		constants.CodeAndIdTokenAndTokenResponse,
	)
}

func (provider *OpenIdProvider) SetScopes(scopes ...string) {
	if slices.Contains(scopes, constants.OpenIdScope) {
		provider.Scopes = scopes
	} else {
		provider.Scopes = append(scopes, constants.OpenIdScope)
	}
}

func (provider *OpenIdProvider) EnablePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.ParLifetimeSecs = parLifetimeSecs
	provider.ParIsEnabled = true
}

func (provider *OpenIdProvider) RequirePushedAuthorizationRequests(parLifetimeSecs int) {
	provider.EnablePushedAuthorizationRequests(parLifetimeSecs)
	provider.ParIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationRequests(
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.JarIsEnabled = true
	provider.JarSignatureAlgorithms = jarAlgorithms
}

func (provider *OpenIdProvider) RequireJwtSecuredAuthorizationRequests(
	jarAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableJwtSecuredAuthorizationRequests(jarAlgorithms...)
	provider.JarIsRequired = true
}

func (provider *OpenIdProvider) EnableJwtSecuredAuthorizationResponseMode(
	jarmLifetimeSecs int,
	defaultJarmSignatureKeyId string,
	jarmSignatureKeyIds ...string,
) {
	if !unit.ContainsAll(jarmSignatureKeyIds, defaultJarmSignatureKeyId) {
		jarmSignatureKeyIds = append(jarmSignatureKeyIds, defaultJarmSignatureKeyId)
	}

	provider.JarmIsEnabled = true
	provider.ResponseModes = append(
		provider.ResponseModes,
		constants.JwtResponseMode,
		constants.QueryJwtResponseMode,
		constants.FragmentJwtResponseMode,
		constants.FormPostJwtResponseMode,
	)
	provider.JarmLifetimeSecs = jarmLifetimeSecs
	provider.DefaultJarmSignatureKeyId = defaultJarmSignatureKeyId
	provider.JarmSignatureKeyIds = jarmSignatureKeyIds

}

func (provider *OpenIdProvider) EnableSecretPostClientAuthn() {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.ClientSecretPostAuthn)
}

func (provider *OpenIdProvider) EnablePrivateKeyJwtClientAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.PrivateKeyJwtAuthn)
	provider.PrivateKeyJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.PrivateKeyJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableClientSecretJwtAuthn(assertionLifetimeSecs int, signatureAlgorithms ...jose.SignatureAlgorithm) {
	provider.ClientAuthnMethods = append(provider.ClientAuthnMethods, constants.ClientSecretBasicAuthn)
	provider.ClientSecretJwtAssertionLifetimeSecs = assertionLifetimeSecs
	provider.ClientSecretJwtSignatureAlgorithms = signatureAlgorithms
}

func (provider *OpenIdProvider) EnableIssuerResponseParameter() {
	provider.IssuerResponseParameterIsEnabled = true
}

func (provider *OpenIdProvider) EnableDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.DpopIsEnabled = true
	provider.DpopLifetimeSecs = dpopLifetimeSecs
	provider.DpopSignatureAlgorithms = dpopSigningAlgorithms
}

func (provider *OpenIdProvider) RequireDemonstrationProofOfPossesion(
	dpopLifetimeSecs int,
	dpopSigningAlgorithms ...jose.SignatureAlgorithm,
) {
	provider.EnableDemonstrationProofOfPossesion(dpopLifetimeSecs, dpopSigningAlgorithms...)
	provider.DpopIsRequired = true
}

func (provider *OpenIdProvider) EnableProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.CodeChallengeMethods = codeChallengeMethods
	provider.PkceIsEnabled = true
}

func (provider *OpenIdProvider) RequireProofKeyForCodeExchange(codeChallengeMethods ...constants.CodeChallengeMethod) {
	provider.EnableProofKeyForCodeExchange(codeChallengeMethods...)
	provider.PkceIsRequired = true
}

func (provider *OpenIdProvider) SetAuthenticationSessionTimeout(timeoutSecs int) {
	provider.AuthenticationSessionTimeoutSecs = timeoutSecs
}

func (provider *OpenIdProvider) AddClient(client models.Client) error {
	return provider.ClientManager.Create(client)
}

func (provider *OpenIdProvider) AddPolicy(policy utils.AuthnPolicy) {
	provider.Policies = append(provider.Policies, policy)
}

func (provider OpenIdProvider) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		provider.Configuration,
		requestContext,
	)
}

func (provider *OpenIdProvider) setUp() {

	// Configure the server.
	provider.Server.Use(func(ctx *gin.Context) {
		// Set the correlation ID to be used in the logs.
		correlationId := ctx.GetHeader(string(constants.CorrelationIdHeader))
		if correlationId == "" {
			correlationId = uuid.NewString()
		}
		ctx.Set(constants.CorrelationIdKey, correlationId)

		// Avoiding caching.
		ctx.Writer.Header().Set("Cache-Control", "no-cache, no-store")
		ctx.Writer.Header().Set("Pragma", "no-cache")
	})

	// Set endpoints.
	provider.Server.GET(
		string(constants.JsonWebKeySetEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleJWKSRequest(provider.getContext(requestCtx))
		},
	)

	if provider.ParIsEnabled {
		provider.Server.POST(
			string(constants.PushedAuthorizationRequestEndpoint),
			func(requestCtx *gin.Context) {
				apihandlers.HandlePARRequest(provider.getContext(requestCtx))
			},
		)
	}

	provider.Server.GET(
		string(constants.AuthorizationEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleAuthorizeRequest(provider.getContext(requestCtx))
		},
	)

	provider.Server.POST(
		string(constants.AuthorizationEndpoint)+"/:callback",
		func(requestCtx *gin.Context) {
			apihandlers.HandleAuthorizeCallbackRequest(provider.getContext(requestCtx))
		},
	)

	provider.Server.POST(
		string(constants.TokenEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleTokenRequest(provider.getContext(requestCtx))
		},
	)

	provider.Server.GET(
		string(constants.WellKnownEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleWellKnownRequest(provider.getContext(requestCtx))
		},
	)

	provider.Server.GET(
		string(constants.UserInfoEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleUserInfoRequest(provider.getContext(requestCtx))
		},
	)

	provider.Server.POST(
		string(constants.UserInfoEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleUserInfoRequest(provider.getContext(requestCtx))
		},
	)

	if provider.DcrIsEnabled {
		provider.Server.POST(
			string(constants.DynamicClientEndpoint),
			func(requestCtx *gin.Context) {
				apihandlers.HandleDynamicClientCreation(provider.getContext(requestCtx))
			},
		)

		provider.Server.PUT(
			string(constants.DynamicClientEndpoint)+"/:client_id",
			func(requestCtx *gin.Context) {
				apihandlers.HandleDynamicClientUpdate(provider.getContext(requestCtx))
			},
		)

		provider.Server.GET(
			string(constants.DynamicClientEndpoint)+"/:client_id",
			func(requestCtx *gin.Context) {
				apihandlers.HandleDynamicClientRetrieve(provider.getContext(requestCtx))
			},
		)

		provider.Server.DELETE(
			string(constants.DynamicClientEndpoint)+"/:client_id",
			func(requestCtx *gin.Context) {
				apihandlers.HandleDynamicClientDelete(provider.getContext(requestCtx))
			},
		)
	}

	provider.Server.POST(
		string(constants.TokenIntrospectionEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleIntrospectionRequest(provider.getContext(requestCtx))
		},
	)
}

func (provider *OpenIdProvider) Run(port int) {
	provider.validateConfiguration()
	provider.setUp()
	provider.Server.Run(":" + fmt.Sprint(port))
}

func (provider *OpenIdProvider) RunTLS(port int) {
	provider.validateConfiguration()
	provider.setUp()
	provider.Server.RunTLS(":"+fmt.Sprint(port), "cert.pem", "key.pem")
}
