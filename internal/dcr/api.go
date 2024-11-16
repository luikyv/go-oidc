package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if config.DCRIsEnabled {
		router.HandleFunc(
			"POST "+config.EndpointPrefix+config.EndpointDCR,
			oidc.Handler(config, handleCreate),
		)

		router.HandleFunc(
			"PUT "+config.EndpointPrefix+config.EndpointDCR+"/{client_id}",
			oidc.Handler(config, handleUpdate),
		)

		router.HandleFunc(
			"GET "+config.EndpointPrefix+config.EndpointDCR+"/{client_id}",
			oidc.Handler(config, handleGet),
		)

		router.HandleFunc(
			"DELETE "+config.EndpointPrefix+config.EndpointDCR+"/{client_id}",
			oidc.Handler(config, handleDelete),
		)
	}
}

func handleCreate(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		err = goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not parse the request", err)
		ctx.WriteError(err)
		return
	}

	initialToken, _ := ctx.BearerToken()
	resp, err := create(ctx, initialToken, req.ClientMetaInfo)
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
		err = goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not parse the request", err)
		ctx.WriteError(err)
		return
	}

	regToken, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	id := ctx.Request.PathValue("client_id")
	resp, err := update(ctx, id, regToken, req.ClientMetaInfo)
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
