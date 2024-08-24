package dcr

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	if config.DCR.IsEnabled {
		router.HandleFunc(
			"POST "+config.Endpoint.Prefix+config.Endpoint.DCR,
			handlerCreate(config),
		)

		router.HandleFunc(
			"PUT "+config.Endpoint.Prefix+config.Endpoint.DCR+"/{client_id}",
			handlerUpdate(config),
		)

		router.HandleFunc(
			"GET "+config.Endpoint.Prefix+config.Endpoint.DCR+"/{client_id}",
			handlerGet(config),
		)

		router.HandleFunc(
			"DELETE "+config.Endpoint.Prefix+config.Endpoint.DCR+"/{client_id}",
			handlerDelete(config),
		)
	}
}

func handlerCreate(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		var req request
		if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
			ctx.WriteError(err)
			return
		}

		req.initialAccessToken = ctx.BearerToken()

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

		var req request
		if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
			ctx.WriteError(err)
			return
		}

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
			return
		}

		req.id = ctx.Request().PathValue("client_id")
		req.registrationAccessToken = token
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
			ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
			return
		}

		req := request{
			id:                      ctx.Request().PathValue("client_id"),
			registrationAccessToken: token,
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
			ctx.WriteError(oidcerr.New(oidcerr.CodeAccessDenied, "no token found"))
			return
		}

		req := request{
			id:                      ctx.Request().PathValue("client_id"),
			registrationAccessToken: token,
		}

		if err := remove(ctx, req); err != nil {
			ctx.WriteError(err)
			return
		}

		ctx.Response().WriteHeader(http.StatusNoContent)
	}

}
