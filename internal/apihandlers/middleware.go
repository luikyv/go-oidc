package apihandlers

import (
	"context"
	"net/http"

	"github.com/google/uuid"
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

type AddCacheControlHeadersMiddlewareHandler struct {
	NextHandler http.Handler
}

func NewAddCacheControlHeadersMiddlewareHandler(next http.Handler) AddCacheControlHeadersMiddlewareHandler {
	return AddCacheControlHeadersMiddlewareHandler{
		NextHandler: next,
	}
}

func (handler AddCacheControlHeadersMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler.NextHandler.ServeHTTP(w, r)
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
}

type AddCorrelationIdHeaderMiddlewareHandler struct {
	NextHandler         http.Handler
	CorrelationIdHeader string
}

func NewAddCorrelationIdHeaderMiddlewareHandler(
	next http.Handler,
	correlationIdHeader string,
) AddCorrelationIdHeaderMiddlewareHandler {
	return AddCorrelationIdHeaderMiddlewareHandler{
		NextHandler:         next,
		CorrelationIdHeader: correlationIdHeader,
	}
}

func (handler AddCorrelationIdHeaderMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	correlationId := uuid.NewString()
	correlationIdHeader, ok := r.Header[string(handler.CorrelationIdHeader)]
	if ok && len(correlationIdHeader) > 0 {
		correlationId = correlationIdHeader[0]
	}

	w.Header().Set(string(handler.CorrelationIdHeader), correlationId)

	ctx := context.WithValue(r.Context(), constants.CorrelationId, correlationId)
	handler.NextHandler.ServeHTTP(w, r.WithContext(ctx))
}
