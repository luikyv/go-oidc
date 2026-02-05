package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	router.Handle("GET "+config.WellKnownEndpoint, goidc.ApplyMiddlewares(oidc.Handler(config, handleWellKnown), middlewares...))

	router.Handle("GET "+config.EndpointPrefix+config.JWKSEndpoint, goidc.ApplyMiddlewares(oidc.Handler(config, handleJWKS), middlewares...))
}

func handleWellKnown(ctx oidc.Context) {
	openidConfig := NewOIDCConfig(ctx)
	if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleJWKS(ctx oidc.Context) {
	jwks, err := ctx.PublicJWKS()
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(jwks, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
