package apihandlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleJWKSRequest(ctx utils.Context) {
	ctx.RequestContext.JSON(http.StatusAccepted, unit.GetPublicKeys())
}

//---------------------------------------- Pushed Authorization Request - PAR ----------------------------------------//

func HandlePARRequest(ctx utils.Context) {
	var req models.PARRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	clientIdBasic, clientSecretBasic, hasBasicAuthn := ctx.RequestContext.Request.BasicAuth()
	if hasBasicAuthn {
		req.ClientIdBasicAuthn = clientIdBasic
		req.ClientSecretBasicAuthn = clientSecretBasic
	}

	if err := req.IsValid(); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	requestUri, err := utils.PushAuthorization(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusAccepted, models.PARResponse{
		RequestUri: requestUri,
		ExpiresIn:  constants.PARLifetimeSecs,
	})
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx utils.Context) {
	var req models.AuthorizeRequest
	if err := ctx.RequestContext.ShouldBindQuery(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	if err := req.IsValid(); err != nil {
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
	err := utils.ContinueAuthentication(ctx, ctx.RequestContext.Param("callback"))
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

	clientIdBasic, clientSecretBasic, hasBasicAuthn := ctx.RequestContext.Request.BasicAuth()
	if hasBasicAuthn {
		req.ClientIdBasicAuthn = clientIdBasic
		req.ClientSecretBasicAuthn = clientSecretBasic
	}

	if err := req.IsValid(); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	tokenSession, err := utils.HandleTokenCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusAccepted, models.TokenResponse{
		AccessToken:  tokenSession.Token,
		IdToken:      tokenSession.IdToken,
		RefreshToken: tokenSession.RefreshToken,
		ExpiresIn:    tokenSession.ExpiresInSecs,
		TokenType:    constants.Bearer,
	})
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx utils.Context) {
	ctx.RequestContext.JSON(http.StatusOK, gin.H{
		"sub": "luiky",
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
