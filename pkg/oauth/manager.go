package oauth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OpenIDManager struct {
	host                string
	scopeManager        crud.ScopeManager
	grantModelManager   crud.GrantModelManager
	clientManager       crud.ClientManager
	grantSessionManager crud.GrantSessionManager
	authnSessionManager crud.AuthnSessionManager
	privateJwks         jose.JSONWebKeySet
	jarmKeyId           string
	policies            []utils.AuthnPolicy
	server              *gin.Engine
}

func NewManager(
	host string,
	privateJWKS jose.JSONWebKeySet,
	templates string,
	settings ...func(*OpenIDManager),
) *OpenIDManager {

	manager := &OpenIDManager{
		host:        host,
		privateJwks: privateJWKS,
		policies:    make([]utils.AuthnPolicy, 0),
		server:      gin.Default(),
	}
	manager.server.LoadHTMLGlob(templates)

	for _, setting := range settings {
		setting(manager)
	}

	return manager
}

func ConfigureInMemoryClientAndScope(manager *OpenIDManager) {
	manager.clientManager = mock.NewMockedClientManager()
	manager.scopeManager = mock.NewMockedScopeManager()
}

func ConfigureInMemoryGrantModel(manager *OpenIDManager) {
	manager.grantModelManager = mock.NewMockedGrantModelManager()
}

func ConfigureInMemorySessions(manager *OpenIDManager) {
	manager.grantSessionManager = mock.NewMockedGrantSessionManager()
	manager.authnSessionManager = mock.NewMockedAuthnSessionManager()
}

func (manager *OpenIDManager) AddGrantModel(model models.GrantModel) error {
	return manager.grantModelManager.Create(model)
}

func (manager *OpenIDManager) AddClient(client models.Client) error {
	return manager.clientManager.Create(client)
}

func (manager *OpenIDManager) AddPolicy(policy utils.AuthnPolicy) {
	manager.policies = append(manager.policies, policy)
}

func (manager OpenIDManager) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		manager.host,
		manager.scopeManager,
		manager.grantModelManager,
		manager.clientManager,
		manager.grantSessionManager,
		manager.authnSessionManager,
		manager.privateJwks,
		manager.jarmKeyId,
		manager.policies,
		requestContext,
	)
}

func (manager *OpenIDManager) run() {

	// Configure the server.
	manager.server.Use(func(ctx *gin.Context) {
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
	manager.server.GET(string(constants.WellKnownEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleWellKnownRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.GET(string(constants.JsonWebKeySetEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleJWKSRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST(string(constants.PushedAuthorizationRequestEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandlePARRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.GET(string(constants.AuthorizationEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleAuthorizeRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST(string(constants.AuthorizationCallbackEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleAuthorizeCallbackRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST(string(constants.TokenEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleTokenRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.GET(string(constants.UserInfoEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleUserInfoRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST(string(constants.UserInfoEndpoint), func(requestCtx *gin.Context) {
		apihandlers.HandleUserInfoRequest(
			manager.getContext(requestCtx),
		)
	})
}

func (manager *OpenIDManager) Run(port int) {
	manager.run()
	// Start the server.
	manager.server.Run(":" + fmt.Sprint(port))
}

func (manager *OpenIDManager) RunTLS(port int) {
	manager.run()
	// Start the server.
	manager.server.RunTLS(":"+fmt.Sprint(port), "cert.pem", "key.pem")
}
