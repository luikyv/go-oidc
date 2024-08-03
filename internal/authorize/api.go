package authorize

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/utils"
)

func HandlerPush(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)

		req := newPushedAuthorizationRequest(ctx.Request())
		requestURI, err := pushAuthorization(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		resp := pushedAuthorizationResponse{
			RequestURI: requestURI,
			ExpiresIn:  ctx.ParLifetimeSecs,
		}
		if err := ctx.Write(resp, http.StatusCreated); err != nil {
			ctx.WriteError(err)
		}
	}
}

func Handler(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)

		req := newAuthorizationRequest(ctx.Request())

		err := initAuth(ctx, req)
		if err != nil {
			err = ctx.ExecuteAuthorizeErrorPlugin(err)
		}

		if err != nil {
			ctx.WriteError(err)
		}
	}

}

func HandlerCallback(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)

		callbackID := ctx.Request().PathValue("callback")
		err := continueAuth(ctx, callbackID)
		if err == nil {
			return
		}

		err = ctx.ExecuteAuthorizeErrorPlugin(err)
		if err != nil {
			ctx.WriteError(err)
		}
	}

}
