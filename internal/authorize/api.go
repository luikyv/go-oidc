package authorize

import (
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if config.PARIsEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.PAREndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerPush), middlewares...))
	}

	if slices.Contains(config.GrantTypes, goidc.GrantCIBA) {
		router.Handle("POST "+config.EndpointPrefix+config.CIBAEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCIBA), middlewares...))
	}

	router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...))
	router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...))

	router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
	router.Handle("POST "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.AuthorizationEndpoint+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...))

}

func handlerPush(ctx oidc.Context) {
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
		return
	}

	req := newFormRequest(ctx.Request)
	resp, err := pushAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		ctx.WriteError(err)
	}
}

func handler(ctx oidc.Context) {
	var req request
	if ctx.Request.Method == http.MethodPost {
		if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
			ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
			return
		}
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	err := initAuth(ctx, req)
	if err != nil {
		if err := ctx.RenderError(err); err != nil {
			ctx.WriteError(err)
		}
		return
	}
}

func handlerCallback(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	err := continueAuth(ctx, callbackID)
	if err == nil {
		return
	}

	err = ctx.RenderError(err)
	if err != nil {
		ctx.WriteError(err)
	}

}

func handlerCIBA(ctx oidc.Context) {
	if mediaType := ctx.MediaType(); mediaType != "" && mediaType != "application/x-www-form-urlencoded" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid content type").WithStatusCode(http.StatusUnsupportedMediaType))
		return
	}

	req := newFormRequest(ctx.Request)
	resp, err := initBackAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
