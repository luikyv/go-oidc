package vc

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.VCIsEnabled {
		return
	}
	router.Handle("GET "+config.EndpointPrefix+config.VCOfferEndpoint+"/{id}", goidc.ApplyMiddlewares(oidc.Handler(config, handleOffer), middlewares...))
}

func handleOffer(ctx oidc.Context) {
	id := ctx.Request.PathValue("id")
	offer, err := offer(ctx, id)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(offer, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
