package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"POST "+config.EndpointPrefix+config.EndpointToken,
		oidc.Handler(config, handleCreate),
	)

	if config.IntrospectionIsEnabled {
		router.HandleFunc(
			"POST "+config.EndpointPrefix+config.EndpointIntrospection,
			oidc.Handler(config, handleIntrospect),
		)
	}
}

func handleCreate(ctx *oidc.Context) {
	req := newRequest(ctx.Request)
	tokenResp, err := generateGrant(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleIntrospect(ctx *oidc.Context) {
	req := newIntrospectionRequest(ctx.Request)
	tokenInfo, err := introspect(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
