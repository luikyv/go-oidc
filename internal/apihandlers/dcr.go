package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/luikymagno/goidc/internal/oauth/dcr"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func HandleDynamicClientCreation(ctx utils.OAuthContext) {
	var req utils.DynamicClientRequest
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	initialAccessToken, _ := ctx.GetBearerToken()
	req.InitialAccessToken = initialAccessToken

	resp, err := dcr.CreateClient(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.WriteJSON(resp, http.StatusCreated); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

func HandleDynamicClientUpdate(ctx utils.OAuthContext) {
	var req utils.DynamicClientRequest
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req.ID = ctx.Request.PathValue("client_id")
	req.RegistrationAccessToken = token
	resp, err := dcr.UpdateClient(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.WriteJSON(resp, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

func HandleDynamicClientRetrieve(ctx utils.OAuthContext) {
	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req := utils.DynamicClientRequest{
		ID:                      ctx.Request.PathValue("client_id"),
		RegistrationAccessToken: token,
	}

	resp, err := dcr.GetClient(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.WriteJSON(resp, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

func HandleDynamicClientDelete(ctx utils.OAuthContext) {
	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(ctx, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "no token found"))
		return
	}

	req := utils.DynamicClientRequest{
		ID:                      ctx.Request.PathValue("client_id"),
		RegistrationAccessToken: token,
	}

	if err := dcr.DeleteClient(ctx, req); err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	ctx.Response.WriteHeader(http.StatusNoContent)
}
