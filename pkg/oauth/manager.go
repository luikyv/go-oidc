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
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OAuthManager struct {
	ScopeManager        crud.ScopeManager
	TokenModelManager   crud.TokenModelManager
	ClientManager       crud.ClientManager
	TokenSessionManager crud.TokenSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	server              *gin.Engine
}

func NewManager(
	privateJWKS jose.JSONWebKeySet,
	settings ...func(*OAuthManager),
) *OAuthManager {

	manager := &OAuthManager{
		server: gin.Default(),
	}

	for _, setting := range settings {
		setting(manager)
	}

	unit.SetPrivateJWKS(privateJWKS)

	return manager
}

func SetMockedEntitiesConfig(manager *OAuthManager) {
	manager.ScopeManager = mock.NewMockedScopeManager()
	manager.TokenModelManager = mock.NewMockedTokenModelManager()
	manager.ClientManager = mock.NewMockedClientManager()
}

func SetMockedSessionsConfig(manager *OAuthManager) {
	manager.TokenSessionManager = mock.NewMockedTokenSessionManager()
	manager.AuthnSessionManager = mock.NewMockedAuthnSessionManager()
}

func (manager *OAuthManager) AddTokenModel(model models.TokenModel) error {
	return manager.TokenModelManager.Create(model)
}

func (manager *OAuthManager) AddClient(client models.Client) error {
	return manager.ClientManager.Create(client)
}

func (manager *OAuthManager) AddPolicy(policy utils.AuthnPolicy) {
	utils.AddPolicy(policy)
}

func (manager OAuthManager) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		manager.ScopeManager,
		manager.TokenModelManager,
		manager.ClientManager,
		manager.TokenSessionManager,
		manager.AuthnSessionManager,
		requestContext,
	)
}

func (manager *OAuthManager) Run(port int) {

	// Configure the server.
	manager.server.LoadHTMLGlob("../cmd/templates/*")
	manager.server.Use(func(ctx *gin.Context) {
		// Set the correlation ID to be used in the logs.
		correlationId := ctx.GetHeader(string(constants.CorrelationIdHeader))
		if correlationId == "" {
			correlationId = uuid.NewString()
		}
		ctx.Set(constants.CorrelationIdKey, correlationId)
	})

	// Set endpoints.
	manager.server.GET("/jwks.json", func(requestCtx *gin.Context) {
		apihandlers.HandleJWKSRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST("/par", func(requestCtx *gin.Context) {
		apihandlers.HandlePARRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.GET("/authorize", func(requestCtx *gin.Context) {
		apihandlers.HandleAuthorizeRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST("/authorize/:callback", func(requestCtx *gin.Context) {
		apihandlers.HandleAuthorizeCallbackRequest(
			manager.getContext(requestCtx),
		)
	})
	manager.server.POST("/token", func(requestCtx *gin.Context) {
		apihandlers.HandleTokenRequest(
			manager.getContext(requestCtx),
		)
	})

	// Start the server.
	manager.server.Run(":" + fmt.Sprint(port))
}
