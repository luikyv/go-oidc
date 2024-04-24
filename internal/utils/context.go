package utils

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type Context struct {
	ScopeManager        crud.ScopeManager
	GrantModelManager   crud.GrantModelManager
	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	PolicyIds           []string
	RequestContext      *gin.Context
	Logger              *slog.Logger
}

func NewContext(
	scopeManager crud.ScopeManager,
	grantModelManager crud.GrantModelManager,
	clientManager crud.ClientManager,
	grantSessionManager crud.GrantSessionManager,
	authnSessionManager crud.AuthnSessionManager,
	policyIds []string,
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
		PolicyIds:           policyIds,
		RequestContext:      reqContext,
		Logger:              logger,
	}
}
