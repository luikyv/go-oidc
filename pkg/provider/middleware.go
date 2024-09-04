package provider

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type cacheControlMiddleware struct {
	nextHandler http.Handler
}

func newCacheControlMiddleware(next http.Handler) cacheControlMiddleware {
	return cacheControlMiddleware{
		nextHandler: next,
	}
}

func (handler cacheControlMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: Add this middleware per endpoint.
	// if strings.Contains(r.RequestURI, goidc.EndpointAuthorize) {
	// 	handler.nextHandler.ServeHTTP(w, r)
	// 	return
	// }

	// Avoid caching.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	handler.nextHandler.ServeHTTP(w, r)
}

// clientCertificateMiddleware should be used when running the server in TLS
// mode and mTLS is enabled.
type clientCertificateMiddleware struct {
	nextHandler http.Handler
}

func newClientCertificateMiddleware(next http.Handler) clientCertificateMiddleware {
	return clientCertificateMiddleware{
		nextHandler: next,
	}
}

func (handler clientCertificateMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Transmit the client certificate in a header.
	r.Header.Set(goidc.HeaderClientCert, string(r.TLS.PeerCertificates[0].Raw)) // TODO: Must encode it. Generate pem version.
	handler.nextHandler.ServeHTTP(w, r)
}
