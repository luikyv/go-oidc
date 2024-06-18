package apihandlers

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type WrapHandlerFunc func(nextHandler http.Handler) http.Handler

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
	// If the correlation ID header is present, use its value.
	// Otherwise, generate a random uuid.
	var correlationId string
	correlationIdHeader, ok := r.Header[handler.CorrelationIdHeader]
	if ok && len(correlationIdHeader) > 0 {
		correlationId = correlationIdHeader[0]
	} else {
		correlationId = uuid.NewString()
	}

	// Return the correlation ID in the response.
	w.Header().Set(handler.CorrelationIdHeader, correlationId)

	// Add the correlation ID to the context.
	ctx := context.WithValue(r.Context(), constants.CorrelationIdKey, correlationId)
	handler.NextHandler.ServeHTTP(w, r.WithContext(ctx))
}

// This middleware should be used when running the server in TLS mode and mTLS is enabled.
type AddClientCertificateHeaderMiddlewareHandler struct {
	NextHandler http.Handler
}

func NewAddCertificateHeaderMiddlewareHandler(next http.Handler) AddClientCertificateHeaderMiddlewareHandler {
	return AddClientCertificateHeaderMiddlewareHandler{
		NextHandler: next,
	}
}

func (handler AddClientCertificateHeaderMiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	certHeader := constants.InsecureClientCertificateHeader
	// If a chain was built linking the client certificate and one of the trusted certificate authorities,
	// consider the certificate secure.
	if len(r.TLS.VerifiedChains) > 0 {
		certHeader = constants.SecureClientCertificateHeader
	}

	// Transmit the client certificate in a header.
	r.Header.Set(certHeader, string(r.TLS.PeerCertificates[0].Raw)) // TODO: Must encode it. Generate pem version.
	handler.NextHandler.ServeHTTP(w, r)
}
