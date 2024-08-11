package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration) {
	router.HandleFunc(
		"POST "+config.PathPrefix+goidc.EndpointUserInfo,
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

		if userInfoResponse.JWTClaims != "" {
			err = ctx.WriteJWT(userInfoResponse.JWTClaims, http.StatusOK)
		} else {
			err = ctx.Write(userInfoResponse.Claims, http.StatusOK)
		}

		if err != nil {
			ctx.WriteError(err)
		}
	}
}
