package utils

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type Context struct {
	ScopeManager        crud.ScopeManager
	GrantModelManager   crud.GrantModelManager
	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	Policies            []AuthnPolicy
	RequestContext      *gin.Context
	Logger              *slog.Logger
}

func NewContext(
	scopeManager crud.ScopeManager,
	grantModelManager crud.GrantModelManager,
	clientManager crud.ClientManager,
	grantSessionManager crud.GrantSessionManager,
	authnSessionManager crud.AuthnSessionManager,
	policies []AuthnPolicy,
	reqContext *gin.Context,
) Context {

	// Create logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	// Set shared information.
	correlationId, _ := reqContext.MustGet(constants.CorrelationIdKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(constants.CorrelationIdKey, correlationId),
	)

	return Context{
		ScopeManager:        scopeManager,
		GrantModelManager:   grantModelManager,
		ClientManager:       clientManager,
		GrantSessionManager: grantSessionManager,
		AuthnSessionManager: authnSessionManager,
		Policies:            policies,
		RequestContext:      reqContext,
		Logger:              logger,
	}
}

func (ctx Context) GetAvailablePolicy(session models.AuthnSession) (policy AuthnPolicy, policyIsAvailable bool) {
	for _, policy = range ctx.Policies {
		if policyIsAvailable = policy.IsAvailableFunc(session, ctx.RequestContext); policyIsAvailable {
			break
		}
	}
	return policy, policyIsAvailable
}
