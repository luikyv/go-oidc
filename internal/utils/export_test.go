package utils

import (
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

var ValidClientSecret = "password"

var ValidTokenModel models.OpaqueTokenModel
var ValidClient models.Client

func init() {

	ValidTokenModel = models.OpaqueTokenModel{
		TokenLength: 20,
		BaseTokenModel: models.BaseTokenModel{
			Id:            "my_token_model",
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
		},
	}

	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(ValidClientSecret), 0)
	ValidClient = models.Client{
		Id:                  "random_client_id",
		RedirectUris:        []string{"https://example.com"},
		Scopes:              []string{"scope1", "scope2"},
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: ValidTokenModel.Id,
		Authenticator: models.SecretClientAuthenticator{
			HashedSecret: string(clientHashedSecret),
		},
	}
}

func SetUp() (ctx Context, tearDown func()) {
	ctx = GetMockedContext()
	ctx.CrudManager.TokenModelManager.Create(ValidTokenModel)
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
		TokenSessionManager: mock.NewMockedTokenSessionManager(),
		AuthnSessionManager: mock.NewMockedAuthnSessionManager(),
	}

	return Context{
		CrudManager:    crudManager,
		RequestContext: GetMockedRequestContext(),
	}
}
