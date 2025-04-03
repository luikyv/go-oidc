package federation

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if !config.OpenIDFedIsEnabled {
		return
	}
	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.OpenIDFedEndpoint,
		oidc.Handler(config, handleFetchStatement),
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
