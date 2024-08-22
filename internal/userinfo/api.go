package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"POST "+config.Endpoint.Prefix+config.Endpoint.UserInfo,
		handler(config),
	)

	router.HandleFunc(
		"GET "+config.Endpoint.Prefix+config.Endpoint.UserInfo,
		handler(config),
	)
}

func handler(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		var err error
		userInfoResponse, err := userInfo(ctx)
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
}
