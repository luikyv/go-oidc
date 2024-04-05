package utils

import (
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

const ValidClientId string = "random_client_id"

const ValidClientSecret string = "password"

const ValidTokenModelId string = "random_token_model"

func SetUp() (ctx Context, tearDown func()) {
	// Create
	tokenModel := models.OpaqueTokenModel{
		TokenLength: 20,
		TokenModelInfo: models.TokenModelInfo{
			Id:            ValidTokenModelId,
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: true,
		},
	}

	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(ValidClientSecret), 0)
	client := models.Client{
		Id:                  "random_client_id",
		RedirectUris:        []string{"https://example.com"},
		Scopes:              []string{"scope1", "scope2"},
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: ValidTokenModelId,
		Authenticator: models.SecretClientAuthenticator{
			HashedSecret: string(clientHashedSecret),
		},
	}

	// Save
	ctx = GetMockedContext()
	ctx.CrudManager.TokenModelManager.Create(tokenModel)
	ctx.CrudManager.ClientManager.Create(client)

	return ctx, func() {
		ctx.CrudManager.TokenModelManager.Delete(ValidTokenModelId)
		ctx.CrudManager.ClientManager.Delete(ValidClientId)
	}
}

func GetMockedRequestContext() *gin.Context {
	gin.SetMode(gin.TestMode)
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
		Logger:         slog.Default(),
	}
}

func GetSessionsFromMock(ctx Context) []models.AuthnSession {
	sessionManager, _ := ctx.CrudManager.AuthnSessionManager.(*mock.MockedAuthnSessionManager)
	sessions := make([]models.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetTokenFromMock(ctx Context) []models.TokenSession {
	tokenManager, _ := ctx.CrudManager.TokenSessionManager.(*mock.MockedTokenSessionManager)
	tokens := make([]models.TokenSession, 0, len(tokenManager.TokenSessions))
	for _, t := range tokenManager.TokenSessions {
		tokens = append(tokens, t)
	}

	return tokens
}
