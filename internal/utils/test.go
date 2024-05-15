package utils

import (
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
)

func init() {
	TestStepMap = stepMap
}

var TestStepMap map[string]AuthnStep

const (
	TestHost string = "https://example.com"
)

func SetUpTest() (testCtx Context, tearDownTest func()) {
	// Create
	privateJwk := unit.GetTestPrivateRs256Jwk("rsa256_key")
	grantModel := models.GetTestOpaqueGrantModel(TestHost, privateJwk)
	client := models.GetSecretPostTestClient()

	// Save
	testCtx = GetTestInMemoryContext(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJwk}})
	testCtx.GrantModelManager.Create(grantModel)
	testCtx.ClientManager.Create(client)

	return testCtx, func() {
		testCtx.GrantModelManager.Delete(grantModel.Meta.Id)
		testCtx.ClientManager.Delete(client.Id)
	}
}

func GetTestInMemoryRequestContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = &http.Request{}
	return ctx
}

func GetTestInMemoryContext(privateJWKS jose.JSONWebKeySet) Context {
	return Context{
		Configuration: Configuration{
			Host:                TestHost,
			ScopeManager:        inmemory.NewInMemoryScopeManager(),
			GrantModelManager:   inmemory.NewInMemoryGrantModelManager(),
			ClientManager:       inmemory.NewInMemoryClientManager(),
			GrantSessionManager: inmemory.NewInMemoryGrantSessionManager(),
			AuthnSessionManager: inmemory.NewInMemoryAuthnSessionManager(),
			ParIsEnabled:        true,
			JarIsEnabled:        true,
			PrivateJwks:         privateJWKS,
			Policies:            []AuthnPolicy{},
		},
		RequestContext: GetTestInMemoryRequestContext(),
		Logger:         slog.Default(),
	}
}

func GetDummyTestContext() Context {
	return Context{
		Configuration: Configuration{
			Host: TestHost,
		},
		Logger: slog.Default(),
	}
}

func GetSessionsFromTestContext(ctx Context) []models.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.InMemoryAuthnSessionManager)
	sessions := make([]models.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetGrantSessionsFromTestContext(ctx Context) []models.GrantSession {
	tokenManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]models.GrantSession, 0, len(tokenManager.GrantSessions))
	for _, t := range tokenManager.GrantSessions {
		tokens = append(tokens, t)
	}

	return tokens
}
