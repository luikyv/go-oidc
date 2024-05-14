package oauth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/apihandlers"
	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type OpenIDManager struct {
	utils.Configuration
	Server *gin.Engine
}

func NewManager(
	host string,
	privateJwks jose.JSONWebKeySet,
	templates string,
	settings ...func(*OpenIDManager),
) *OpenIDManager {

	manager := &OpenIDManager{
		Configuration: utils.Configuration{
			Host:        host,
			PrivateJwks: privateJwks,
			Policies:    make([]utils.AuthnPolicy, 0),
		},
		Server: gin.Default(),
	}
	manager.Server.LoadHTMLGlob(templates)

	for _, setting := range settings {
		setting(manager)
	}

	return manager
}

func ConfigureInMemoryClientAndScope(manager *OpenIDManager) {
	manager.ClientManager = inmemory.NewInMemoryClientManager()
	manager.ScopeManager = inmemory.NewInMemoryScopeManager()
}

func ConfigureInMemoryGrantModel(manager *OpenIDManager) {
	manager.GrantModelManager = inmemory.NewInMemoryGrantModelManager()
}

func ConfigureInMemorySessions(manager *OpenIDManager) {
	manager.GrantSessionManager = inmemory.NewInMemoryGrantSessionManager()
	manager.AuthnSessionManager = inmemory.NewInMemoryAuthnSessionManager()
}

func (manager *OpenIDManager) EnablePushedAuthorizationRequests(
	isRequired bool,
) {
	manager.ParIsEnabled = true
	manager.ParIsRequired = isRequired
}

func (manager *OpenIDManager) EnableJwtSecuredAuthorizationRequests(
	privateJarKeyId string,
	isRequired bool,
) {
	manager.JarIsEnabled = true
	manager.PrivateJarmKeyId = privateJarKeyId
	manager.JarIsRequired = isRequired
}

func (manager *OpenIDManager) AddGrantModel(model models.GrantModel) error {
	return manager.GrantModelManager.Create(model)
}

func (manager *OpenIDManager) AddClient(client models.Client) error {
	return manager.ClientManager.Create(client)
}

func (manager *OpenIDManager) AddPolicy(policy utils.AuthnPolicy) {
	manager.Policies = append(manager.Policies, policy)
}

func (manager OpenIDManager) getContext(requestContext *gin.Context) utils.Context {
	return utils.NewContext(
		manager.Configuration,
		requestContext,
	)
}

func (manager *OpenIDManager) setUp() {

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

func (manager *OpenIDManager) Run(port int) {
	manager.setUp()
	manager.Server.Run(":" + fmt.Sprint(port))
}

func (manager *OpenIDManager) RunTLS(port int) {
	manager.setUp()
	manager.Server.RunTLS(":"+fmt.Sprint(port), "cert.pem", "key.pem")
}
