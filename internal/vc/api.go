package vc

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.VCISelfEnabled {
		return
	}

	router.Handle("GET /.well-known/openid-credential-issuer",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleMetadata), middlewares...))
	if config.VCISelfOffersEnabled {
		router.Handle("GET "+config.EndpointPrefix+config.VCISelfOfferEndpoint+"/{id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handleOffer), middlewares...))
	}
	router.Handle("POST "+config.EndpointPrefix+config.VCISelfCredentialEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCredential), middlewares...))
}

func handleMetadata(ctx oidc.Context) {
	if err := ctx.Write(newMetadata(ctx), http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleCredential(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		return
	}

	resp, err := issue(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
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
