package utils

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type Context struct {
	CrudManager    crud.CRUDManager
	RequestContext *gin.Context
	Logger         *slog.Logger
}

func NewContext(crudManager crud.CRUDManager, reqContext *gin.Context) Context {

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
		CrudManager:    crudManager,
		RequestContext: reqContext,
		Logger:         logger,
	}
}
