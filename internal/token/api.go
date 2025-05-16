package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointToken,
		goidc.CacheControlMiddleware(oidc.Handler(config, handleCreate)),
	)

	if config.TokenIntrospectionIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointIntrospection,
			goidc.CacheControlMiddleware(oidc.Handler(config, handleIntrospection)),
		)
	}

	if config.TokenRevocationIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointTokenRevocation,
			goidc.CacheControlMiddleware(oidc.Handler(config, handleRevocation)),
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
