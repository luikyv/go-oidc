package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"POST "+config.EndpointPrefix+config.EndpointUserInfo,
		oidc.Handler(config, handle),
	)

	router.HandleFunc(
		"GET "+config.EndpointPrefix+config.EndpointUserInfo,
		oidc.Handler(config, handle),
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
