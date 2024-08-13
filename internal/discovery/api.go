package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"GET "+config.Endpoint.Prefix+config.Endpoint.JWKS,
		handlerJWKS(config),
	)

	router.HandleFunc(
		"GET "+config.Endpoint.Prefix+config.Endpoint.WellKnown,
		handlerWellKnown(config),
	)
}

func handlerWellKnown(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		openidConfig := oidcConfig(ctx)
		if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func handlerJWKS(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)
		if err := ctx.Write(ctx.PublicKeys(), http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}
