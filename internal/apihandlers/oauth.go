package apihandlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/unit"
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

	requestUri, err := oauth.PushAuthorization(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusCreated, models.PARResponse{
		RequestUri: requestUri,
		ExpiresIn:  constants.ParLifetimeSecs,
	})
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx utils.Context) {
	var req models.AuthorizationRequest
	if err := ctx.RequestContext.ShouldBindQuery(&req); err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	err := oauth.InitAuth(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}
}

func HandleAuthorizeCallbackRequest(ctx utils.Context) {
	err := oauth.ContinueAuth(ctx, ctx.RequestContext.Param("callback"))
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

	grantSession, err := utils.HandleGrantCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	ctx.RequestContext.JSON(http.StatusOK, models.TokenResponse{
		AccessToken:  grantSession.Token,
		IdToken:      grantSession.IdToken,
		RefreshToken: grantSession.RefreshToken,
		ExpiresIn:    grantSession.ExpiresInSecs,
		TokenType:    constants.Bearer,
	})
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx utils.Context) {
	token, ok := unit.GetBearerToken(ctx.RequestContext)
	if !ok {
		bindErrorToResponse(issues.OAuthBaseError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "no token found",
		}, ctx.RequestContext)
		return
	}

	grantSession, err := oauth.HandleUserInfoRequest(ctx, token)
	if err != nil {
		bindErrorToResponse(err, ctx.RequestContext)
		return
	}

	response := gin.H{string(constants.SubjectClaim): grantSession.Subject}
	for k, v := range grantSession.AdditionalIdTokenClaims {
		response[k] = v
	}

	ctx.RequestContext.JSON(http.StatusOK, response)
}

//---------------------------------------- Helpers ----------------------------------------//

func bindErrorToResponse(err error, requestContext *gin.Context) {

	// TODO
	var oauthErr issues.OAuthBaseError
	if errors.As(err, &oauthErr) {
		requestContext.JSON(http.StatusBadRequest, gin.H{
			"error":             oauthErr.ErrorCode,
			"error_description": oauthErr.ErrorDescription,
		})
		return
	}

	var oauthRedirectErr issues.OAuthRedirectError
	if errors.As(err, &oauthRedirectErr) {
		requestContext.JSON(http.StatusBadRequest, gin.H{
			"error":             oauthRedirectErr.ErrorCode,
			"error_description": oauthRedirectErr.ErrorDescription,
		})
		return
	}

	requestContext.JSON(http.StatusBadRequest, gin.H{
		"error":             constants.AccessDenied,
		"error_description": err.Error(),
	})
}

func addBasicCredentialsToRequest(ctx utils.Context, req *models.ClientAuthnRequest) {
	clientIdBasic, clientSecretBasic, hasBasicAuthn := ctx.RequestContext.Request.BasicAuth()
	if hasBasicAuthn {
		req.ClientIdBasicAuthn = clientIdBasic
		req.ClientSecretBasicAuthn = clientSecretBasic
	}
}
