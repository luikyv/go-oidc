package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"GET "+config.PathPrefix+goidc.EndpointJSONWebKeySet,
		handlerJWKS(config),
	)

	router.HandleFunc(
		"GET "+config.PathPrefix+goidc.EndpointWellKnown,
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
