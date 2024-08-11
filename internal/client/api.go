package client

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if config.DCRIsEnabled {
		router.HandleFunc(
			"POST "+config.PathPrefix+goidc.EndpointDynamicClient,
			handlerCreate(config),
		)

		router.HandleFunc(
			"PUT "+config.PathPrefix+goidc.EndpointDynamicClient+"/{client_id}",
			handlerUpdate(config),
		)

		router.HandleFunc(
			"GET "+config.PathPrefix+goidc.EndpointDynamicClient+"/{client_id}",
			handlerGet(config),
		)

		router.HandleFunc(
			"DELETE "+config.PathPrefix+goidc.EndpointDynamicClient+"/{client_id}",
			handlerDelete(config),
		)
	}
}

func handlerCreate(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		var req DynamicClientRequest
		if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
			ctx.WriteError(err)
			return
		}

		req.InitialAccessToken = ctx.BearerToken()

		resp, err := create(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(resp, http.StatusCreated); err != nil {
			ctx.WriteError(err)
		}
	}
}

func handlerUpdate(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		var req DynamicClientRequest
		if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
			ctx.WriteError(err)
			return
		}

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidc.NewError(oidc.ErrorCodeAccessDenied, "no token found"))
			return
		}

		req.ID = ctx.Request().PathValue("client_id")
		req.RegistrationAccessToken = token
		resp, err := update(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(resp, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func handlerGet(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidc.NewError(oidc.ErrorCodeAccessDenied, "no token found"))
			return
		}

		req := DynamicClientRequest{
			ID:                      ctx.Request().PathValue("client_id"),
			RegistrationAccessToken: token,
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

}

func handlerDelete(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidc.NewError(oidc.ErrorCodeAccessDenied, "no token found"))
			return
		}

		req := DynamicClientRequest{
			ID:                      ctx.Request().PathValue("client_id"),
			RegistrationAccessToken: token,
		}

		if err := remove(ctx, req); err != nil {
			ctx.WriteError(err)
			return
		}

		ctx.Response().WriteHeader(http.StatusNoContent)
	}

}
