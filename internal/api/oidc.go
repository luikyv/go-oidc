package api

import (
	"errors"
	"net/http"

	"github.com/luikyv/goidc/internal/oauth/authorize"
	"github.com/luikyv/goidc/internal/oauth/discovery"
	"github.com/luikyv/goidc/internal/oauth/introspection"
	"github.com/luikyv/goidc/internal/oauth/par"
	"github.com/luikyv/goidc/internal/oauth/token"
	"github.com/luikyv/goidc/internal/oauth/userinfo"
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

//---------------------------------------- Well Known ----------------------------------------//

func HandleWellKnownRequest(ctx *utils.Context) {
	if err := ctx.Write(discovery.GetOpenIDConfiguration(ctx), http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- JWKS ----------------------------------------//

func HandleJWKSRequest(ctx *utils.Context) {
	if err := ctx.Write(ctx.PublicKeys(), http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- Pushed Authorization Request - PAR ----------------------------------------//

func HandleParRequest(ctx *utils.Context) {
	req := utils.NewPushedAuthorizationRequest(ctx.Request())
	requestURI, err := par.PushAuthorization(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	resp := utils.PushedAuthorizationResponse{
		RequestURI: requestURI,
		ExpiresIn:  ctx.ParLifetimeSecs,
	}
	if err := ctx.Write(resp, http.StatusCreated); err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- Authorize ----------------------------------------//

func HandleAuthorizeRequest(ctx *utils.Context) {
	req := utils.NewAuthorizationRequest(ctx.Request())

	err := authorize.InitAuth(ctx, req)
	if err != nil {
		err = ctx.ExecuteAuthorizeErrorPlugin(err)
	}

	if err != nil {
		writeError(ctx, err)
	}
}

func HandleAuthorizeCallbackRequest(ctx *utils.Context) {
	err := authorize.ContinueAuth(ctx, ctx.Request().PathValue("callback"))
	if err != nil {
		err = ctx.ExecuteAuthorizeErrorPlugin(err)
	}

	if err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- Token ----------------------------------------//

func HandleTokenRequest(ctx *utils.Context) {
	req := utils.NewTokenRequest(ctx.Request())
	tokenResp, err := token.HandleTokenCreation(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- User Info ----------------------------------------//

func HandleUserInfoRequest(ctx *utils.Context) {

	var err error
	userInfoResponse, err := userinfo.HandleUserInfoRequest(ctx)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if userInfoResponse.JWTClaims != "" {
		err = ctx.WriteJWT(userInfoResponse.JWTClaims, http.StatusOK)
	} else {
		err = ctx.Write(userInfoResponse.Claims, http.StatusOK)
	}
	if err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- Introspection ----------------------------------------//

func HandleIntrospectionRequest(ctx *utils.Context) {
	req := utils.NewTokenIntrospectionRequest(ctx.Request())
	tokenInfo, err := introspection.IntrospectToken(ctx, req)
	if err != nil {
		writeError(ctx, err)
		return
	}

	if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
		writeError(ctx, err)
	}
}

//---------------------------------------- Helpers ----------------------------------------//

func writeError(ctx *utils.Context, err error) {

	var oauthErr goidc.OAuthError
	if !errors.As(err, &oauthErr) {
		if err := ctx.Write(map[string]any{
			"error":             goidc.ErrorCodeInternalError,
			"error_description": err.Error(),
		}, http.StatusInternalServerError); err != nil {
			ctx.Response().WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	errorCode := oauthErr.Code()
	if err := ctx.Write(map[string]any{
		"error":             errorCode,
		"error_description": oauthErr.Error(),
	}, errorCode.StatusCode()); err != nil {
		ctx.Response().WriteHeader(http.StatusInternalServerError)
	}
}
