package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
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

func handleCreate(ctx *oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		err = oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not parse the request", err)
		ctx.WriteError(err)
		return
	}

	if t, ok := ctx.BearerToken(); ok {
		req.initialToken = t
	}

	resp, err := create(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		ctx.WriteError(err)
	}
}

func handleUpdate(ctx *oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		err = oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not parse the request", err)
		ctx.WriteError(err)
		return
	}

	token, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
		return
	}

	req.id = ctx.Request.PathValue("client_id")
	req.registrationToken = token
	resp, err := update(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleGet(ctx *oidc.Context) {
	token, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
		return
	}

	req := request{
		id:                ctx.Request.PathValue("client_id"),
		registrationToken: token,
	}

	resp, err := fetch(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleDelete(ctx *oidc.Context) {
	token, ok := ctx.BearerToken()
	if !ok {
		ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
		return
	}

	req := request{
		id:                ctx.Request.PathValue("client_id"),
		registrationToken: token,
	}

	if err := remove(ctx, req); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.Response.WriteHeader(http.StatusNoContent)
}
