package oauth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OAuthManager struct {
	crudManager crud.CRUDManager
	server      *gin.Engine
}

// Create a new OAuthManager.
// By default, all internal manager are set to store infomation in memory.
func NewManager() *OAuthManager {
	manager := &OAuthManager{
		crudManager: crud.CRUDManager{},
		server:      gin.Default(),
	}
	manager.setMockedConfig()
	return manager
}

func (manager *OAuthManager) setMockedConfig() {
	manager.crudManager = crud.CRUDManager{
		ScopeManager:        mock.NewMockedScopeManager(),
		TokenModelManager:   mock.NewMockedTokenModelManager(),
		ClientManager:       mock.NewMockedClientManager(),
		TokenSessionManager: mock.NewTokenSessionManager(),
		AuthnSessionManager: mock.NewMockedAuthnSessionManager(),
	}
}

func (manager *OAuthManager) AddTokenModel(model models.TokenModel) error {
	return manager.crudManager.TokenModelManager.Create(model)
}

func (manager *OAuthManager) AddClient(client models.Client) error {
	return manager.crudManager.ClientManager.Create(client)
}

func (manager *OAuthManager) Run(port int) {

	// Set endpoints.
	manager.server.POST("/token", func(ctx *gin.Context) {
		apihandlers.HandleTokenRequest(utils.Context{CrudManager: manager.crudManager, RequestContext: ctx})
	})
	manager.server.GET("/authorize", func(ctx *gin.Context) {
		apihandlers.HandleAuthorizeRequest(
			utils.Context{CrudManager: manager.crudManager, RequestContext: ctx},
		)
	})
	manager.server.GET("/authorize/:callback", func(ctx *gin.Context) {
		apihandlers.HandleAuthorizeCallbackRequest(
			utils.Context{CrudManager: manager.crudManager, RequestContext: ctx},
		)
	})

	// Start the server.
	manager.server.Run(":" + fmt.Sprint(port))
}
