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
	TokenModelManager   crud.TokenModelManager
	ClientManager       crud.ClientManager
	TokenSessionManager crud.TokenSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	RequestContext      *gin.Context
	Logger              *slog.Logger
}

func NewContext(
	scopeManager crud.ScopeManager,
	tokenModelManager crud.TokenModelManager,
	clientManager crud.ClientManager,
	tokenSessionManager crud.TokenSessionManager,
	authnSessionManager crud.AuthnSessionManager,
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
		TokenModelManager:   tokenModelManager,
		ClientManager:       clientManager,
		TokenSessionManager: tokenSessionManager,
		AuthnSessionManager: authnSessionManager,
		RequestContext:      reqContext,
		Logger:              logger,
	}
}
