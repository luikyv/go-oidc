package discovery

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func HandlerWellKnown(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		openidConfig := oidcConfig(ctx)
		if err := ctx.Write(openidConfig, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func HandlerJWKS(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)
		if err := ctx.Write(ctx.PublicKeys(), http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}
