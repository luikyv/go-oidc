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

type OpenIdManager struct {
	utils.Configuration
	Server *gin.Engine
}

func NewManager(
	host string,
	privateJwks jose.JSONWebKeySet,
	templates string,
	settings ...func(*OpenIdManager),
) *OpenIdManager {

	manager := &OpenIdManager{
		Configuration: utils.Configuration{
			Host:        host,
			PrivateJwks: privateJwks,
			Policies:    make([]utils.AuthnPolicy, 0),
			ResponseModes: []constants.ResponseMode{
				constants.QueryResponseMode,
				constants.FragmentResponseMode,
				constants.FormPostResponseMode,
			},
			ClientAuthnMethods:      []constants.ClientAuthnType{constants.NoneAuthn, constants.ClientSecretBasicAuthn, constants.ClientSecretPostAuthn},
			ClientSigningAlgorithms: []jose.SignatureAlgorithm{},
		},
		Server: gin.Default(),
	}
	manager.Server.LoadHTMLGlob(templates)

	for _, setting := range settings {
		setting(manager)
	}

	return manager
}

func ConfigureInMemoryClientAndScope(manager *OpenIdManager) {
	manager.ClientManager = inmemory.NewInMemoryClientManager()
	manager.ScopeManager = inmemory.NewInMemoryScopeManager()
}

func ConfigureInMemoryGrantModel(manager *OpenIdManager) {
	manager.GrantModelManager = inmemory.NewInMemoryGrantModelManager()
}

func ConfigureInMemorySessions(manager *OpenIdManager) {
	manager.GrantSessionManager = inmemory.NewInMemoryGrantSessionManager()
	manager.AuthnSessionManager = inmemory.NewInMemoryAuthnSessionManager()
}

func (manager *OpenIdManager) RequirePushedAuthorizationRequests() {
	manager.ParIsEnabled = true
	manager.ParIsRequired = true
}

func (manager *OpenIdManager) EnablePushedAuthorizationRequests() {
	manager.ParIsEnabled = true
	manager.ParIsRequired = false
}

func (manager *OpenIdManager) RequireJwtSecuredAuthorizationRequests(
	jarAlgorithms []jose.SignatureAlgorithm,
) {
	manager.JarIsEnabled = true
	manager.JarIsRequired = true
	manager.JarAlgorithms = jarAlgorithms
}

func (manager *OpenIdManager) EnableJwtSecuredAuthorizationRequests(
	jarAlgorithms []jose.SignatureAlgorithm,
) {
	manager.JarIsEnabled = true
	manager.JarIsRequired = false
	manager.JarAlgorithms = jarAlgorithms
}

func (manager *OpenIdManager) EnableJwtSecuredAuthorizationResponseMode(
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

func (manager *OpenIdManager) SetClientAuthnMethods(methods ...constants.ClientAuthnType) {
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

func (manager *OpenIdManager) EnableIssuerResponseParameter() {
	manager.IssuerResponseParameterIsEnabled = true
}

func (manager *OpenIdManager) AddGrantModel(model models.GrantModel) error {
	return manager.GrantModelManager.Create(model)
}

func (manager *OpenIdManager) AddClient(client models.Client) error {
	return manager.ClientManager.Create(client)
}

func (manager *OpenIdManager) AddPolicy(policy utils.AuthnPolicy) {
	manager.Policies = append(manager.Policies, policy)
}

func (manager OpenIdManager) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		manager.Configuration,
		requestContext,
	)
}

func (manager *OpenIdManager) setUp() {

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

func (manager *OpenIdManager) Run(port int) {
	manager.setUp()
	manager.Server.Run(":" + fmt.Sprint(port))
}

func (manager *OpenIdManager) RunTLS(port int) {
	manager.setUp()
	manager.Server.RunTLS(":"+fmt.Sprint(port), "cert.pem", "key.pem")
}
