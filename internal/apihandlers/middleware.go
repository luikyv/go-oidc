package apihandlers

import (
	"net/http"

	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AddCertificateHeaderMiddlewareHandler struct {
	NextHandler http.Handler
}

func NewAddCertificateHeaderMiddlewareHandler(next http.Handler) AddCertificateHeaderMiddlewareHandler {
	return AddCertificateHeaderMiddlewareHandler{
		NextHandler: next,
	}
}

func (handler AddCertificateHeaderMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set(string(constants.ClientCertificateHeader), string(r.TLS.PeerCertificates[0].Raw)) // TODO: should I encode it?
	handler.NextHandler.ServeHTTP(w, r)
}
