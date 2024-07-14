package apihandlers

import (
	"errors"
	"net/http"

	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/oauth/discovery"
	"github.com/luikymagno/goidc/internal/oauth/introspection"
	"github.com/luikymagno/goidc/internal/oauth/par"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/oauth/userinfo"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

//---------------------------------------- Well Known ----------------------------------------//

func HandleWellKnownRequest(ctx *utils.Context) {
	if err := ctx.Write(discovery.GetOpenIDConfiguration(ctx), http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- JWKS ----------------------------------------//

func HandleJWKSRequest(ctx *utils.Context) {
	if err := ctx.Write(ctx.PublicKeys(), http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Pushed Authorization Request - PAR ----------------------------------------//

func HandleParRequest(ctx *utils.Context) {
	req := utils.NewPushedAuthorizationRequest(ctx.Request)
	requestURI, err := par.PushAuthorization(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	resp := utils.PushedAuthorizationResponse{
		RequestURI: requestURI,
		ExpiresIn:  ctx.ParLifetimeSecs,
	}
	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx *utils.Context) {
	req := utils.NewAuthorizationRequest(ctx.Request)
	if err := authorize.InitAuth(ctx, req); err != nil {
		bindErrorToResponse(ctx, err)
		return
	}
}

func HandleAuthorizeCallbackRequest(ctx *utils.Context) {
	err := authorize.ContinueAuth(ctx, ctx.Request.PathValue("callback"))
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}
}

//---------------------------------------- Token ----------------------------------------//

func HandleTokenRequest(ctx *utils.Context) {
	req := utils.NewTokenRequest(ctx.Request)
	tokenResp, err := token.HandleTokenCreation(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx *utils.Context) {

	var err error
	userInfoResponse, err := userinfo.HandleUserInfoRequest(ctx)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if userInfoResponse.JWTClaims != "" {
		err = ctx.WriteJWT(userInfoResponse.JWTClaims, http.StatusOK)
	} else {
		err = ctx.Write(userInfoResponse.Claims, http.StatusOK)
	}
	if err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Introspection ----------------------------------------//

func HandleIntrospectionRequest(ctx *utils.Context) {
	req := utils.NewTokenIntrospectionRequest(ctx.Request)
	tokenInfo, err := introspection.IntrospectToken(ctx, req)
	if err != nil {
		bindErrorToResponse(ctx, err)
		return
	}

	if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
		bindErrorToResponse(ctx, err)
	}
}

//---------------------------------------- Helpers ----------------------------------------//

func bindErrorToResponse(ctx *utils.Context, err error) {

	var oauthErr goidc.OAuthError
	if !errors.As(err, &oauthErr) {
		if err := ctx.Write(map[string]any{
			"error":             goidc.ErrorCodeInternalError,
			"error_description": err.Error(),
		}, http.StatusInternalServerError); err != nil {
			ctx.Response.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	errorCode := oauthErr.Code()
	if err := ctx.Write(map[string]any{
		"error":             errorCode,
		"error_description": oauthErr.Error(),
	}, errorCode.StatusCode()); err != nil {
		ctx.Response.WriteHeader(http.StatusInternalServerError)
	}
}
