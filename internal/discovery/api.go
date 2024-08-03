package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/utils"
)

func HandlerWellKnown(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)

		openidConfig := wellKnown(ctx)
		if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func HandlerJWKS(config *utils.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := utils.NewContext(*config, r, w)
		if err := ctx.Write(ctx.PublicKeys(), http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}
