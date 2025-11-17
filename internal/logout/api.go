package logout

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.LogoutIsEnabled {
		return
	}

	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointLogout,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...),
	)
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointLogout,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...),
	)

	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointLogout+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...),
	)
	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointLogout+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...),
	)
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointLogout+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...),
	)
	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointLogout+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...),
	)
}

func handle(ctx oidc.Context) {
	var req request
	if ctx.RequestMethod() == http.MethodPost {
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	if err := initLogout(ctx, req); err != nil {
		if err := ctx.RenderError(err); err != nil {
			ctx.WriteError(err)
		}
		return
	}
}

func handleCallback(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	err := continueLogout(ctx, callbackID)
	if err != nil {
		ctx.WriteError(err)
		return
	}
}
