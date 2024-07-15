package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type WrapHandlerFunc func(nextHandler http.Handler) http.Handler

type CacheControlMiddleware struct {
	NextHandler http.Handler
}

func NewCacheControlMiddleware(next http.Handler) CacheControlMiddleware {
	return CacheControlMiddleware{
		NextHandler: next,
	}
}

func (handler CacheControlMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.RequestURI, string(goidc.EndpointAuthorization)) {
		handler.NextHandler.ServeHTTP(w, r)
		return
	}

	// Avoid caching.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	handler.NextHandler.ServeHTTP(w, r)
}

type CorrelationIDMiddleware struct {
	NextHandler         http.Handler
	CorrelationIDHeader string
}

func NewCorrelationIDMiddleware(
	next http.Handler,
	correlationIDHeader string,
) CorrelationIDMiddleware {
	return CorrelationIDMiddleware{
		NextHandler:         next,
		CorrelationIDHeader: correlationIDHeader,
	}
}

func (handler CorrelationIDMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If the correlation ID header is present, use its value.
	// Otherwise, generate a random uuid.
	var correlationID string
	correlationIDHeader, ok := r.Header[handler.CorrelationIDHeader]
	if ok && len(correlationIDHeader) > 0 {
		correlationID = correlationIDHeader[0]
	} else {
		correlationID = uuid.NewString()
	}

	// Return the correlation ID in the response.
	w.Header().Set(handler.CorrelationIDHeader, correlationID)

	// Add the correlation ID to the context.
	ctx := context.WithValue(r.Context(), goidc.CorrelationIDKey, correlationID)
	handler.NextHandler.ServeHTTP(w, r.WithContext(ctx))
}

// This middleware should be used when running the server in TLS mode and mTLS is enabled.
type ClientCertificateMiddleware struct {
	NextHandler http.Handler
}

func NewClientCertificateMiddleware(next http.Handler) ClientCertificateMiddleware {
	return ClientCertificateMiddleware{
		NextHandler: next,
	}
}

func (handler ClientCertificateMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	certHeader := goidc.HeaderInsecureClientCertificate
	// If a chain was built linking the client certificate and one of the trusted certificate authorities,
	// consider the certificate secure.
	if len(r.TLS.VerifiedChains) > 0 {
		certHeader = goidc.HeaderSecureClientCertificate
	}

	// Transmit the client certificate in a header.
	r.Header.Set(certHeader, string(r.TLS.PeerCertificates[0].Raw)) // TODO: Must encode it. Generate pem version.
	handler.NextHandler.ServeHTTP(w, r)
}
