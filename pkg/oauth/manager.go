package oauth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OAuthManager struct {
	crudManager crud.CRUDManager
	server      *gin.Engine
}

func NewManager(settings ...func(*OAuthManager)) *OAuthManager {
	manager := &OAuthManager{
		crudManager: crud.CRUDManager{},
		server:      gin.Default(),
	}

	for _, setting := range settings {
		setting(manager)
	}

	return manager
}

func SetMockedEntitiesConfig(manager *OAuthManager) {
	manager.crudManager.ScopeManager = mock.NewMockedScopeManager()
	manager.crudManager.TokenModelManager = mock.NewMockedTokenModelManager()
	manager.crudManager.ClientManager = mock.NewMockedClientManager()
}

func SetMockedSessionsConfig(manager *OAuthManager) {
	manager.crudManager.TokenSessionManager = mock.NewMockedTokenSessionManager()
	manager.crudManager.AuthnSessionManager = mock.NewMockedAuthnSessionManager()
}

func (manager *OAuthManager) AddTokenModel(model models.TokenModel) error {
	errorCh := make(chan error)
	manager.crudManager.TokenModelManager.Create(model, errorCh)
	return <-errorCh
}

func (manager *OAuthManager) AddClient(client models.Client) error {
	errorCh := make(chan error)
	manager.crudManager.ClientManager.Create(client, errorCh)
	return <-errorCh
}

func (manager *OAuthManager) AddPolicy(policy models.AuthnPolicy) {
	models.AddPolicy(policy)
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
	manager.server.POST("/par", func(ctx *gin.Context) {
		apihandlers.HandlePARRequest(
			utils.NewContext(manager.crudManager, ctx),
		)
	})
	manager.server.GET("/authorize", func(ctx *gin.Context) {
		apihandlers.HandleAuthorizeRequest(
			utils.NewContext(manager.crudManager, ctx),
		)
	})
	manager.server.POST("/authorize/:callback", func(ctx *gin.Context) {
		apihandlers.HandleAuthorizeCallbackRequest(
			utils.NewContext(manager.crudManager, ctx),
		)
	})
	manager.server.POST("/token", func(ctx *gin.Context) {
		apihandlers.HandleTokenRequest(
			utils.NewContext(manager.crudManager, ctx),
		)
	})

	// Start the server.
	manager.server.Run(":" + fmt.Sprint(port))
}
