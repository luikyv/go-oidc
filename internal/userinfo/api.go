package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	router.Handle(
		"POST "+config.EndpointPrefix+config.UserInfoEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...),
	)

	router.Handle(
		"GET "+config.EndpointPrefix+config.UserInfoEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handle), middlewares...),
	)
}

func handle(ctx oidc.Context) {
	var err error
	userInfoResponse, err := handleUserInfoRequest(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if userInfoResponse.jwtClaims != "" {
		err = ctx.WriteJWT(userInfoResponse.jwtClaims, http.StatusOK)
	} else {
		err = ctx.Write(userInfoResponse.claims, http.StatusOK)
	}

	if err != nil {
		ctx.WriteError(err)
	}
}
