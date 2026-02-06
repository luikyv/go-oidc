package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if config.DCRIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.DCREndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleCreate), middlewares...),
		)

		router.Handle(
			"PUT "+config.EndpointPrefix+config.DCREndpoint+"/{client_id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handleUpdate), middlewares...),
		)

		router.Handle(
			"GET "+config.EndpointPrefix+config.DCREndpoint+"/{client_id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handleGet), middlewares...),
		)

		router.Handle(
			"DELETE "+config.EndpointPrefix+config.DCREndpoint+"/{client_id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handleDelete), middlewares...),
		)
	}
}

func handleCreate(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	initialToken, _ := ctx.BearerToken()
	resp, err := create(ctx, initialToken, req.ClientMeta)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		ctx.WriteError(err)
	}
}

func handleUpdate(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	regToken, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	id := ctx.Request.PathValue("client_id")
	resp, err := update(ctx, id, regToken, req.ClientMeta)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleGet(ctx oidc.Context) {
	token, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	resp, err := fetch(ctx, ctx.Request.PathValue("client_id"), token)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleDelete(ctx oidc.Context) {
	token, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	if err := remove(ctx, ctx.Request.PathValue("client_id"), token); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.Response.WriteHeader(http.StatusNoContent)
}
