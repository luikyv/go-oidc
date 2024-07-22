package api

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/goidc/internal/oauth/dcr"
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func HandleDynamicClientCreation(ctx *utils.Context) {
	var req utils.DynamicClientRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		writeError(ctx, err)
		return
	}

	req.InitialAccessToken = ctx.BearerToken()

	resp, err := dcr.CreateClient(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		writeError(ctx, err)
	}
}

func HandleDynamicClientUpdate(ctx *utils.Context) {
	var req utils.DynamicClientRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		writeError(ctx, err)
		return
	}

	token := ctx.BearerToken()
	if token == "" {
		writeError(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req.ID = ctx.Request().PathValue("client_id")
	req.RegistrationAccessToken = token
	resp, err := dcr.UpdateClient(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

func HandleDynamicClientRetrieve(ctx *utils.Context) {
	token := ctx.BearerToken()
	if token == "" {
		writeError(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req := utils.DynamicClientRequest{
		ID:                      ctx.Request().PathValue("client_id"),
		RegistrationAccessToken: token,
	}

	resp, err := dcr.GetClient(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

func HandleDynamicClientDelete(ctx *utils.Context) {
	token := ctx.BearerToken()
	if token == "" {
		writeError(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req := utils.DynamicClientRequest{
		ID:                      ctx.Request().PathValue("client_id"),
		RegistrationAccessToken: token,
	}

	if err := dcr.DeleteClient(ctx, req); err != nil {
		writeError(ctx, err)
		return
	}

	ctx.Response().WriteHeader(http.StatusNoContent)
}
