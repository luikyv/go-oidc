package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointJWKS,
		oidc.Handler(config, handleJWKS),
	)

	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointWellKnown,
		oidc.Handler(config, handleWellKnown),
	)
}

func handleWellKnown(ctx oidc.Context) {
	openidConfig := oidcConfig(ctx)
	if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleJWKS(ctx oidc.Context) {
	jwks, err := ctx.PublicKeys()
	if err != nil {
		ctx.WriteError(goidc.Errorf(goidc.ErrorCodeInternalError,
			"internal error", err))
		return
	}

	if err := ctx.Write(jwks, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
