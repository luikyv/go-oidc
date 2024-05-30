package apihandlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/oauth/authorize"
	"github.com/luikymagno/auth-server/internal/oauth/par"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//---------------------------------------- Well Known ----------------------------------------//

func HandleWellKnownRequest(ctx utils.Context) {
	ctx.RequestContext.JSON(http.StatusOK, oauth.GetOpenIdConfiguration(ctx))
}

//---------------------------------------- JWKS ----------------------------------------//

func HandleJWKSRequest(ctx utils.Context) {
	ctx.RequestContext.JSON(http.StatusOK, ctx.GetPublicKeys())
}

//---------------------------------------- Pushed Authorization Request - PAR ----------------------------------------//

func HandlePARRequest(ctx utils.Context) {
	var req models.PushedAuthorizationRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
	addBasicCredentialsToRequest(ctx, &req.ClientAuthnRequest)

	requestUri, err := par.PushAuthorization(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusCreated, models.PushedAuthorizationResponse{
		RequestUri: requestUri,
		ExpiresIn:  ctx.ParLifetimeSecs,
	})
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx utils.Context) {
	var req models.AuthorizationRequest
	if err := ctx.RequestContext.ShouldBindQuery(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	err := authorize.InitAuth(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
}

func HandleAuthorizeCallbackRequest(ctx utils.Context) {
	err := authorize.ContinueAuth(ctx, ctx.RequestContext.Param("callback"))
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
}

//---------------------------------------- Token ----------------------------------------//

func HandleTokenRequest(ctx utils.Context) {
	var req models.TokenRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
	addBasicCredentialsToRequest(ctx, &req.ClientAuthnRequest)
	addProofOfPossesionToRequest(ctx, &req)

	tokenResp, err := token.HandleTokenCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, tokenResp)
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx utils.Context) {

	userInfoResponse, err := oauth.HandleUserInfoRequest(ctx)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	if userInfoResponse.SignedClaims != "" {
		ctx.RequestContext.Data(http.StatusOK, "application/jwt", []byte(userInfoResponse.SignedClaims))
	} else {
		ctx.RequestContext.JSON(http.StatusOK, userInfoResponse.Claims)
	}
}

//---------------------------------------- Introspection ----------------------------------------//

func HandleIntrospectionRequest(ctx utils.Context) {
	var req models.TokenIntrospectionRequest
	if err := ctx.RequestContext.ShouldBind(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
	addBasicCredentialsToRequest(ctx, &req.ClientAuthnRequest)

	tokenInfo, err := oauth.IntrospectToken(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, tokenInfo.GetParameters())
}

//---------------------------------------- Helpers ----------------------------------------//

func addBasicCredentialsToRequest(ctx utils.Context, req *models.ClientAuthnRequest) {
	clientIdBasic, clientSecretBasic, hasBasicAuthn := ctx.RequestContext.Request.BasicAuth()
	if hasBasicAuthn {
		req.ClientIdBasicAuthn = clientIdBasic
		req.ClientSecretBasicAuthn = clientSecretBasic
	}
}

func addProofOfPossesionToRequest(ctx utils.Context, req *models.TokenRequest) {
	if !ctx.DpopIsEnabled {
		return
	}
	req.DpopJwt = ctx.RequestContext.GetHeader(string(constants.DpopHeader))
}

func bindErrorToResponse(err error, requestContext *gin.Context) {

	var oauthErr models.OAuthError
	if errors.As(err, &oauthErr) {
		errorCode := oauthErr.GetCode()
		requestContext.JSON(errorCode.GetStatusCode(), gin.H{
			"error":             errorCode,
			"error_description": oauthErr.Error(),
		})
		return
	}

	requestContext.JSON(http.StatusBadRequest, gin.H{
		"error":             constants.AccessDenied,
		"error_description": err.Error(),
	})
}
