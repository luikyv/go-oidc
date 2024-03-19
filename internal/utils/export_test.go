package utils

import (
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

var ValidClient models.Client = models.Client{
	Id:            "random_client_id",
	RedirectUris:  []string{"https://example.com"},
	Scopes:        []string{"scope1", "scope2"},
	ResponseTypes: []constants.ResponseType{constants.Code},
}

func SetUp() (ctx Context, tearDown func()) {
	ctx = GetMockedContext()
	ctx.CrudManager.ClientManager.Create(ValidClient)

	return ctx, func() {
		ctx.CrudManager.ClientManager.Delete(ValidClient.Id)
	}
}

func GetMockedRequestContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	// session := &AuthnSession{}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = &http.Request{}
	return ctx
}

func GetMockedContext() Context {
	crudManager := crud.CRUDManager{
		ScopeManager:        mock.NewMockedScopeManager(),
		TokenModelManager:   mock.NewMockedTokenModelManager(),
		ClientManager:       mock.NewMockedClientManager(),
		TokenSessionManager: mock.NewTokenSessionManager(),
		AuthnSessionManager: mock.NewMockedAuthnSessionManager(),
	}

	return Context{
		CrudManager:    crudManager,
		RequestContext: GetMockedRequestContext(),
	}
}
