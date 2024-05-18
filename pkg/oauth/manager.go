package oauth

import (
	"fmt"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OAuthManager struct {
	utils.Configuration
	Server *gin.Engine
}

func NewManager(
	host string,
	privateJwks jose.JSONWebKeySet,
	templates string,
	settings ...func(*OAuthManager),
) *OAuthManager {

	manager := &OAuthManager{
		Configuration: utils.Configuration{
			Host:        host,
			PrivateJwks: privateJwks,
			GrantTypes: []constants.GrantType{
				constants.ClientCredentialsGrant,
				constants.AuthorizationCodeGrant,
				constants.RefreshTokenGrant,
				constants.ImplictGrant,
			},
			ResponseTypes: []constants.ResponseType{
				constants.CodeResponse,
				constants.IdTokenResponse,
				constants.TokenResponse,
				constants.CodeAndIdTokenResponse,
				constants.CodeAndTokenResponse,
				constants.IdTokenAndTokenResponse,
				constants.CodeAndIdTokenAndTokenResponse,
			},
			ResponseModes: []constants.ResponseMode{
				constants.QueryResponseMode,
				constants.FragmentResponseMode,
				constants.FormPostResponseMode,
			},
			ClientAuthnMethods: []constants.ClientAuthnType{
				constants.NoneAuthn,
				constants.ClientSecretBasicAuthn,
				constants.ClientSecretPostAuthn,
			},
			ClientSigningAlgorithms: []jose.SignatureAlgorithm{},
			CodeChallengeMethods: []constants.CodeChallengeMethod{
				constants.SHA256CodeChallengeMethod,
				constants.PlainCodeChallengeMethod,
			},
			DpopSigningAlgorithms: []jose.SignatureAlgorithm{},
			Policies:              make([]utils.AuthnPolicy, 0),
		},
		Server: gin.Default(),
	}
	manager.Server.LoadHTMLGlob(templates)

	for _, setting := range settings {
		setting(manager)
	}

	return manager
}

func ConfigureInMemoryClientAndScope(manager *OAuthManager) {
	manager.ClientManager = inmemory.NewInMemoryClientManager()
	manager.ScopeManager = inmemory.NewInMemoryScopeManager()
}

func ConfigureInMemoryGrantModel(manager *OAuthManager) {
	manager.GrantModelManager = inmemory.NewInMemoryGrantModelManager()
}

func ConfigureInMemorySessions(manager *OAuthManager) {
	manager.GrantSessionManager = inmemory.NewInMemoryGrantSessionManager()
	manager.AuthnSessionManager = inmemory.NewInMemoryAuthnSessionManager()
}

func (manager *OAuthManager) RequirePushedAuthorizationRequests() {
	manager.ParIsEnabled = true
	manager.ParIsRequired = true
}

func (manager *OAuthManager) EnablePushedAuthorizationRequests() {
	manager.ParIsEnabled = true
	manager.ParIsRequired = false
}

func (manager *OAuthManager) RequireJwtSecuredAuthorizationRequests(
	jarAlgorithms []jose.SignatureAlgorithm,
) {
	manager.JarIsEnabled = true
	manager.JarIsRequired = true
	manager.JarAlgorithms = jarAlgorithms
}

func (manager *OAuthManager) EnableJwtSecuredAuthorizationRequests(
	jarAlgorithms []jose.SignatureAlgorithm,
) {
	manager.JarIsEnabled = true
	manager.JarIsRequired = false
	manager.JarAlgorithms = jarAlgorithms
}

func (manager *OAuthManager) EnableJwtSecuredAuthorizationResponseMode(
	privateJarmKeyId string,
) {
	manager.JarmIsEnabled = true
	manager.ResponseModes = []constants.ResponseMode{
		constants.QueryResponseMode,
		constants.QueryJwtResponseMode,
		constants.FragmentResponseMode,
		constants.FragmentJwtResponseMode,
		constants.FormPostResponseMode,
		constants.FormPostJwtResponseMode,
	}
	manager.PrivateJarmKeyId = privateJarmKeyId
}

func (manager *OAuthManager) SetClientAuthnMethods(methods ...constants.ClientAuthnType) {
	signingAlgorithms := []jose.SignatureAlgorithm{}
	if slices.Contains(methods, constants.PrivateKeyJwtAuthn) {
		signingAlgorithms = append(signingAlgorithms, jose.RS256, jose.PS256)
	}
	if slices.Contains(methods, constants.ClientSecretJwt) {
		signingAlgorithms = append(signingAlgorithms, jose.HS256)
	}

	manager.ClientAuthnMethods = methods
	manager.ClientSigningAlgorithms = signingAlgorithms
}

func (manager *OAuthManager) EnableIssuerResponseParameter() {
	manager.IssuerResponseParameterIsEnabled = true
}

func (manager *OAuthManager) EnableDpop(
	dpopSigningAlgorithms []jose.SignatureAlgorithm,
) {
	manager.DpopIsEnabled = true
	manager.DpopIsRequired = false
	manager.DpopSigningAlgorithms = dpopSigningAlgorithms
}

func (manager *OAuthManager) RequireDpop(
	dpopSigningAlgorithms []jose.SignatureAlgorithm,
) {
	manager.DpopIsEnabled = true
	manager.DpopIsRequired = true
	manager.DpopSigningAlgorithms = dpopSigningAlgorithms
}

func (manager *OAuthManager) RequirePkce() {
	manager.PkceIsRequired = true
}

func (manager *OAuthManager) AddGrantModel(model models.GrantModel) error {
	return manager.GrantModelManager.Create(model)
}

func (manager *OAuthManager) AddClient(client models.Client) error {
	return manager.ClientManager.Create(client)
}

func (manager *OAuthManager) AddPolicy(policy utils.AuthnPolicy) {
	manager.Policies = append(manager.Policies, policy)
}

func (manager OAuthManager) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		manager.Configuration,
		requestContext,
	)
}

func (manager *OAuthManager) setUp() {

	// Configure the server.
	manager.Server.Use(func(ctx *gin.Context) {
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
	manager.Server.GET(
		string(constants.WellKnownEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleWellKnownRequest(manager.getContext(requestCtx))
		},
	)
	manager.Server.GET(
		string(constants.JsonWebKeySetEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleJWKSRequest(manager.getContext(requestCtx))
		},
	)
	if manager.ParIsEnabled {
		manager.Server.POST(
			string(constants.PushedAuthorizationRequestEndpoint),
			func(requestCtx *gin.Context) {
				apihandlers.HandlePARRequest(manager.getContext(requestCtx))
			},
		)
	}
	manager.Server.GET(
		string(constants.AuthorizationEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleAuthorizeRequest(manager.getContext(requestCtx))
		},
	)
	manager.Server.POST(
		string(constants.AuthorizationCallbackEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleAuthorizeCallbackRequest(manager.getContext(requestCtx))
		},
	)
	manager.Server.POST(
		string(constants.TokenEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleTokenRequest(manager.getContext(requestCtx))
		},
	)
	manager.Server.GET(
		string(constants.UserInfoEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleUserInfoRequest(manager.getContext(requestCtx))
		},
	)
	manager.Server.POST(
		string(constants.UserInfoEndpoint),
		func(requestCtx *gin.Context) {
			apihandlers.HandleUserInfoRequest(manager.getContext(requestCtx))
		},
	)
}

func (manager *OAuthManager) Run(port int) {
	manager.setUp()
	manager.Server.Run(":" + fmt.Sprint(port))
}

func (manager *OAuthManager) RunTLS(port int) {
	manager.setUp()
	manager.Server.RunTLS(":"+fmt.Sprint(port), "cert.pem", "key.pem")
}
