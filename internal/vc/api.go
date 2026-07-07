package vc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.VCISelfEnabled {
		return
	}

	uri, _ := url.Parse(config.VCISelfHost)
	path := strings.TrimSuffix(uri.Path, "/")

	router.Handle("GET /.well-known/openid-credential-issuer"+path,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleMetadata), middlewares...))

	router.Handle("POST "+config.EndpointPrefix+config.VCISelfCredentialEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCredential), middlewares...))

	if config.VCISelfOffersEnabled {
		router.Handle("GET "+config.EndpointPrefix+config.VCISelfOfferEndpoint+"/{id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handleOffer), middlewares...))
	}

	if config.VCISelfJWTIssuerEnabled {
		router.Handle("GET /.well-known/jwt-vc-issuer"+path,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleJWTIssuerMetadata), middlewares...))
	}

	if config.VCISelfDeferredEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.VCISelfDeferredCredentialEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleDeferredCredential), middlewares...))
	}

	if config.VCISelfNotificationEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.VCISelfNotificationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleNotification), middlewares...))
	}
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

	status := http.StatusOK
	if resp.Deferred {
		status = http.StatusAccepted
	}

	if resp.JWT != "" {
		if err := ctx.WriteJWT(resp.JWT, status); err != nil {
			ctx.WriteError(err)
		}
		return
	}

	if err := ctx.Write(resp, status); err != nil {
		ctx.WriteError(err)
	}
}

func handleDeferredCredential(ctx oidc.Context) {
	var req deferredRequest
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		return
	}

	resp, err := deferredCredential(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	status := http.StatusOK
	if resp.Deferred {
		status = http.StatusAccepted
	}

	if resp.JWT != "" {
		if err := ctx.WriteJWT(resp.JWT, status); err != nil {
			ctx.WriteError(err)
		}
		return
	}

	if err := ctx.Write(resp, status); err != nil {
		ctx.WriteError(err)
	}
}

func handleNotification(ctx oidc.Context) {
	var req notificationRequest
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"))
		return
	}

	if err := notify(ctx, req); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusNoContent)
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

func handleJWTIssuerMetadata(ctx oidc.Context) {
	metadata, err := newJWTIssuerMetadata(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(metadata, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}
