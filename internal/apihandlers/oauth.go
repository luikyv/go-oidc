package apihandlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx utils.Context) {
	var req models.AuthorizeRequest
	if err := ctx.RequestContext.ShouldBindQuery(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	err := utils.InitAuthentication(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
}

func HandleAuthorizeCallbackRequest(ctx utils.Context) {
	err := utils.ContinueAuthentication(ctx, ctx.RequestContext.Param("callback_id"))
	if err != nil {
		ctx.RequestContext.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

//---------------------------------------- Token ----------------------------------------//

func HandleTokenRequest(ctx utils.Context) {
	var req models.TokenRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	token, err := utils.HandleTokenCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusAccepted, models.TokenResponse{
		AccessToken: token.TokenString,
		ExpiresIn:   token.ExpiresInSecs,
		TokenType:   constants.Bearer,
	})
}

//---------------------------------------- Error Handling ----------------------------------------//

func bindErrorToResponse(err error, requestContext *gin.Context) {

	var oauthErr issues.OAuthError
	if errors.As(err, &oauthErr) {
		oauthErr.BindErrorToResponse(requestContext)
		return
	}

	requestContext.JSON(http.StatusBadRequest, gin.H{
		"error":             constants.AccessDenied,
		"error_description": err.Error(),
	})
}
