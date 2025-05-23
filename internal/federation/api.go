package federation

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.OpenIDFedIsEnabled {
		return
	}
	router.Handle(
		"GET "+config.EndpointPrefix+config.OpenIDFedEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleFetchStatement), middlewares...),
	)
}

func handleFetchStatement(ctx oidc.Context) {
	statement, err := newEntityStatement(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.WriteJWTWithType(statement, http.StatusOK, entityStatementJWTContentType); err != nil {
		ctx.WriteError(err)
	}
}
