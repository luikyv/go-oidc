package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"POST "+config.Endpoint.Prefix+config.Endpoint.Token,
		handler(config),
	)

	if config.Introspection.IsEnabled {
		router.HandleFunc(
			"POST "+config.Endpoint.Prefix+config.Endpoint.Introspection,
			handlerIntrospect(config),
		)
	}
}

func handler(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newRequest(ctx.Request())
		tokenResp, err := generateGrant(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}
}

func handlerIntrospect(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newIntrospectionRequest(ctx.Request())
		tokenInfo, err := introspect(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}
}
