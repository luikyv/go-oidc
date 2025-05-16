package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.Handle(
		"POST "+config.EndpointPrefix+config.EndpointUserInfo,
		goidc.CacheControlMiddleware(oidc.Handler(config, handle)),
	)

	router.Handle(
		"GET "+config.EndpointPrefix+config.EndpointUserInfo,
		goidc.CacheControlMiddleware(oidc.Handler(config, handle)),
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
