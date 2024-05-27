package apihandlers

import (
	"net/http"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/dcr"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleDynamicClientCreation(ctx utils.Context) {
	var req models.DynamicClientRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	resp, err := dcr.RegisterClient(ctx, req)
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

	token, ok := unit.GetBearerToken(ctx.RequestContext)
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	resp, err := dcr.UpdateClient(ctx, ctx.RequestContext.Param("client_id"), token, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, resp)
}

func HandleDynamicClientRetrieve(ctx utils.Context) {
	token, ok := unit.GetBearerToken(ctx.RequestContext)
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	resp, err := dcr.GetClient(ctx, ctx.RequestContext.Param("client_id"), token)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, resp)
}

func HandleDynamicClientDelete(ctx utils.Context) {
	token, ok := unit.GetBearerToken(ctx.RequestContext)
	if !ok {
		bindErrorToResponse(models.NewOAuthError(constants.AccessDenied, "no token found"), ctx.RequestContext)
		return
	}

	if err := dcr.DeleteClient(ctx, ctx.RequestContext.Param("client_id"), token); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.Status(http.StatusNoContent)
}
