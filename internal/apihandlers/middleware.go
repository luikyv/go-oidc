package apihandlers

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AddCacheControlHeadersMiddlewareHandler struct {
	NextHandler http.Handler
}

func NewAddCacheControlHeadersMiddlewareHandler(next http.Handler) AddCacheControlHeadersMiddlewareHandler {
	return AddCacheControlHeadersMiddlewareHandler{
		NextHandler: next,
	}
}

func (handler AddCacheControlHeadersMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Avoid caching.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	handler.NextHandler.ServeHTTP(w, r)
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
	correlationIdHeader, ok := r.Header[handler.CorrelationIdHeader]
	if ok && len(correlationIdHeader) > 0 {
		correlationId = correlationIdHeader[0]
	}

	w.Header().Set(handler.CorrelationIdHeader, correlationId)

	ctx := context.WithValue(r.Context(), constants.CorrelationIdKey, correlationId)
	handler.NextHandler.ServeHTTP(w, r.WithContext(ctx))
}

type AddCertificateHeaderMiddlewareHandler struct {
	NextHandler http.Handler
}

func NewAddCertificateHeaderMiddlewareHandler(next http.Handler) AddCertificateHeaderMiddlewareHandler {
	return AddCertificateHeaderMiddlewareHandler{
		NextHandler: next,
	}
}

func (handler AddCertificateHeaderMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	certHeader := constants.InsecureClientCertificateHeader
	// TODO: Make sure this works.
	if len(r.TLS.VerifiedChains) >= 0 {
		certHeader = constants.SecureClientCertificateHeader
	}
	r.Header.Set(certHeader, string(r.TLS.PeerCertificates[0].Raw)) // TODO: should I encode it?
	handler.NextHandler.ServeHTTP(w, r)
}
