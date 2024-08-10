package client

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func HandlerCreate(config oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(config, r, w)

		var req dynamicClientRequest
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

func HandlerUpdate(config oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(config, r, w)

		var req dynamicClientRequest
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

func HandlerGet(config oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(config, r, w)

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidc.NewError(oidc.ErrorCodeAccessDenied, "no token found"))
			return
		}

		req := dynamicClientRequest{
			ID:                      ctx.Request().PathValue("client_id"),
			RegistrationAccessToken: token,
		}

		resp, err := client(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(resp, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func HandlerDelete(config oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(config, r, w)

		token := ctx.BearerToken()
		if token == "" {
			ctx.WriteError(oidc.NewError(oidc.ErrorCodeAccessDenied, "no token found"))
			return
		}

		req := dynamicClientRequest{
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
