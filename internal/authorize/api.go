package authorize

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if config.PARIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointPushedAuthorization,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerPush), middlewares...),
		)
	}

	if config.CIBAIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointCIBA,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerCIBA), middlewares...),
		)
	}

	if config.DeviceAuthorizationIsEnabled {
		// initialize device authorization
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointDeviceAuthorization,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDeviceAuth), middlewares...),
		)
		// user code handling and verification
		router.Handle(
			"GET "+config.EndpointPrefix+config.EndpointDevice,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDevice), middlewares...),
		)
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointDevice,
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDevice), middlewares...),
		)
		// run policy handlers
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointDevice+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDeviceCallback), middlewares...),
		)
		router.Handle(
			"GET "+config.EndpointPrefix+config.EndpointDevice+"/{callback}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDeviceCallback), middlewares...),
		)
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointDevice+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDeviceCallback), middlewares...),
		)
		router.Handle(
			"GET "+config.EndpointPrefix+config.EndpointDevice+"/{callback}/{callback_path...}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlerDeviceCallback), middlewares...),
		)
	}

	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize,
		goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...),
	)
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize,
		goidc.ApplyMiddlewares(oidc.Handler(config, handler), middlewares...),
	)

	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...),
	)
	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...),
	)
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...),
	)
	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}/{callback_path...}",
		goidc.ApplyMiddlewares(oidc.Handler(config, handlerCallback), middlewares...),
	)
}

func handlerPush(ctx oidc.Context) {

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
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	err := initAuth(ctx, req)
	if err != nil {
		err = ctx.RenderError(err)
	}

	if err != nil {
		ctx.WriteError(err)
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

func handlerDeviceAuth(ctx oidc.Context) {
	req := newFormRequest(ctx.Request)
	resp, err := initDeviceAuth(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handlerDevice(ctx oidc.Context) {
	var req request
	if ctx.Request.Method == http.MethodPost {
		req = newFormRequest(ctx.Request)
	} else {
		req = newRequest(ctx.Request)
	}

	err := startDeviceAuth(ctx, req)
	if err == nil {
		return
	}

	err = ctx.RenderError(err)
	if err != nil {
		ctx.WriteError(err)
	}
}

func handlerDeviceCallback(ctx oidc.Context) {
	callbackID := ctx.Request.PathValue("callback")
	err := continueDeviceAuth(ctx, callbackID)
	if err == nil {
		return
	}

	err = ctx.RenderError(err)
	if err != nil {
		ctx.WriteError(err)
	}
}
