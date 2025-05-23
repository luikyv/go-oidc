package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointToken,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCreate), middlewares...),
	)

	if config.TokenIntrospectionIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointIntrospection,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleIntrospection), middlewares...),
		)
	}

	if config.TokenRevocationIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointTokenRevocation,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleRevocation), middlewares...),
		)
	}
}

func handleCreate(ctx oidc.Context) {
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

func handleIntrospection(ctx oidc.Context) {
	req := newQueryRequest(ctx.Request)
	tokenInfo, err := introspect(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleRevocation(ctx oidc.Context) {
	req := newQueryRequest(ctx.Request)
	err := revoke(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusOK)
}
