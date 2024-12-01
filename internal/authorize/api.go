package authorize

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if config.PARIsEnabled {
		router.HandleFunc(
			"POST "+config.EndpointPrefix+config.EndpointPushedAuthorization,
			oidc.Handler(config, handlerPush),
		)
	}

	if config.CIBAIsEnabled {
		router.HandleFunc(
			"POST "+config.EndpointPrefix+config.EndpointCIBA,
			oidc.Handler(config, handlerCIBA),
		)
	}

	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize,
		oidc.Handler(config, handler),
	)
	router.HandleFunc(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize,
		oidc.Handler(config, handler),
	)

	router.HandleFunc(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}",
		oidc.Handler(config, handlerCallback),
	)
	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}",
		oidc.Handler(config, handlerCallback),
	)
	router.HandleFunc(
		"POST "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}/{callback_path...}",
		oidc.Handler(config, handlerCallback),
	)
	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointAuthorize+"/{callback}/{callback_path...}",
		oidc.Handler(config, handlerCallback),
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
