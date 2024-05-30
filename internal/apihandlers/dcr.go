package apihandlers

import (
	"net/http"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/dcr"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleDynamicClientCreation(ctx utils.Context) {
	var req models.DynamicClientRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	initialAccessToken, _ := ctx.GetBearerToken()
	req.InitialAccessToken = initialAccessToken

	resp, err := dcr.CreateClient(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusCreated, resp)
}

func HandleDynamicClientUpdate(ctx utils.Context) {
	var req models.DynamicClientRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	req.Id = ctx.RequestContext.Param("client_id")
	req.RegistrationAccessToken = token
	resp, err := dcr.UpdateClient(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, resp)
}

func HandleDynamicClientRetrieve(ctx utils.Context) {
	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	req := models.DynamicClientRequest{
		Id:                      ctx.RequestContext.Param("client_id"),
		RegistrationAccessToken: token,
	}

	resp, err := dcr.GetClient(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, resp)
}

func HandleDynamicClientDelete(ctx utils.Context) {
	token, ok := ctx.GetBearerToken()
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	req := models.DynamicClientRequest{
		Id:                      ctx.RequestContext.Param("client_id"),
		RegistrationAccessToken: token,
	}

	if err := dcr.DeleteClient(ctx, req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.Status(http.StatusNoContent)
}
