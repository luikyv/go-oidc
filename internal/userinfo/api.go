package userinfo

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/utils"
)

func Handler(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)

		var err error
		userInfoResponse, err := handleUserInfoRequest(ctx)
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
