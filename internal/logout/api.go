package logout

import (
	"errors"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.LogoutEnabled {
		return
	}

	router.Handle("GET "+config.EndpointPrefix+config.LogoutEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...))
	router.Handle("POST "+config.EndpointPrefix+config.LogoutEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...))

	router.Handle("POST "+config.EndpointPrefix+config.LogoutEndpoint+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.LogoutEndpoint+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...))
	router.Handle("POST "+config.EndpointPrefix+config.LogoutEndpoint+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.LogoutEndpoint+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCallback), middlewares...))
}

func handle(ctx oidc.Context) {
	var req request
	if ctx.RequestMethod() == http.MethodPost {
		if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
			ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
				errors.New("content type must be application/x-www-form-urlencoded")).WithStatusCode(http.StatusUnsupportedMediaType))
			return
		}
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
	if err := continueLogout(ctx, callbackID); err != nil {
		if err := ctx.RenderError(err); err != nil {
			ctx.WriteError(err)
		}
		return
	}
}
