package apihandlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth"
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/oauth/par"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/oauth/userinfo"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

//---------------------------------------- Well Known ----------------------------------------//

func HandleWellKnownRequest(ctx utils.Context) {
	if err := ctx.WriteJson(oauth.GetOpenIdConfiguration(ctx), http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- JWKS ----------------------------------------//

func HandleJWKSRequest(ctx utils.Context) {
	if err := ctx.WriteJson(ctx.GetPublicKeys(), http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Pushed Authorization Request - PAR ----------------------------------------//

func HandleParRequest(ctx utils.Context) {
	req := models.NewPushedAuthorizationRequest(ctx.Request)
	requestUri, err := par.PushAuthorization(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	resp := models.PushedAuthorizationResponse{
		RequestUri: requestUri,
		ExpiresIn:  ctx.ParLifetimeSecs,
	}
	if err := ctx.WriteJson(resp, http.StatusCreated); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx utils.Context) {
	req := models.NewAuthorizationRequest(ctx.Request)
	if err := authorize.InitAuth(ctx, req); err != nil {
		bindErrorToResponse(ctx, err)
		return
	}
}

func HandleAuthorizeCallbackRequest(ctx utils.Context) {
	err := authorize.ContinueAuth(ctx, ctx.Request.PathValue("callback"))
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}
}

//---------------------------------------- Token ----------------------------------------//

func HandleTokenRequest(ctx utils.Context) {
	req := models.NewTokenRequest(ctx.Request)
	tokenResp, err := token.HandleTokenCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.WriteJson(tokenResp, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx utils.Context) {

	var err error
	userInfoResponse, err := userinfo.HandleUserInfoRequest(ctx)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if userInfoResponse.JwtClaims != "" {
		err = ctx.WriteJwt(userInfoResponse.JwtClaims, http.StatusOK)
	} else {
		err = ctx.WriteJson(userInfoResponse.Claims, http.StatusOK)
	}
	if err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Introspection ----------------------------------------//

func HandleIntrospectionRequest(ctx utils.Context) {
	req := models.NewTokenIntrospectionRequest(ctx.Request)
	tokenInfo, err := oauth.IntrospectToken(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.WriteJson(tokenInfo, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Helpers ----------------------------------------//

func bindErrorToResponse(ctx utils.Context, err error) {

	var oauthErr models.OAuthError
	if errors.As(err, &oauthErr) {
		ctx.Response.Header().Set("Content-Type", "application/json")
		errorCode := oauthErr.GetCode()
		ctx.Response.WriteHeader(errorCode.GetStatusCode())
		json.NewEncoder(ctx.Response).Encode(map[string]any{
			"error":             errorCode,
			"error_description": oauthErr.Error(),
		})
		return
	}

	ctx.Response.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(ctx.Response).Encode(map[string]any{
		"error":             goidc.InternalError,
		"error_description": err.Error(),
	})
}
