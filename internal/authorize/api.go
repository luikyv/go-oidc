package authorize

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if config.PAR.IsEnabled {
		router.HandleFunc(
			"POST "+config.Endpoint.Prefix+config.Endpoint.PushedAuthorization,
			handlerPush(config),
		)
	}

	router.HandleFunc(
		"GET "+config.Endpoint.Prefix+config.Endpoint.Authorize,
		handler(config),
	)

	router.HandleFunc(
		"POST "+config.Endpoint.Prefix+config.Endpoint.Authorize+"/{callback}",
		handlerCallback(config),
	)
}

func handlerPush(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newPushedRequest(ctx.Request())
		resp, err := pushAuth(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(resp, http.StatusCreated); err != nil {
			ctx.WriteError(err)
		}
	}
}

func handler(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newRequest(ctx.Request())

		err := initAuth(ctx, req)
		if err != nil {
			err = ctx.ExecuteAuthorizeErrorPlugin(err)
		}

		if err != nil {
			ctx.WriteError(err)
		}
	}
}

func handlerCallback(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		callbackID := ctx.Request().PathValue("callback")
		err := continueAuth(ctx, callbackID)
		if err == nil {
			return
		}

		err = ctx.ExecuteAuthorizeErrorPlugin(err)
		if err != nil {
			ctx.WriteError(err)
		}
	}

}
