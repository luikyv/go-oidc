package api

import (
	"net/http"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
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
	// TODO: Add this middleware per endpoint.
	if strings.Contains(r.RequestURI, string(goidc.EndpointAuthorization)) {
		handler.NextHandler.ServeHTTP(w, r)
		return
	}

	// Avoid caching.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	handler.NextHandler.ServeHTTP(w, r)
}

// ClientCertificateMiddleware should be used when running the server in TLS mode and mTLS is enabled.
type ClientCertificateMiddleware struct {
	NextHandler http.Handler
}

func NewClientCertificateMiddleware(next http.Handler) ClientCertificateMiddleware {
	return ClientCertificateMiddleware{
		NextHandler: next,
	}
}

func (handler ClientCertificateMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Transmit the client certificate in a header.
	r.Header.Set(goidc.HeaderClientCertificate, string(r.TLS.PeerCertificates[0].Raw)) // TODO: Must encode it. Generate pem version.
	handler.NextHandler.ServeHTTP(w, r)
}
