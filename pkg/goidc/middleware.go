package goidc

import (
	"encoding/pem"
	"net/http"
	"net/url"
)

func CacheControlMiddleware(next http.Handler) http.Handler {
	// TODO: Skip for the auth endpoint.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid caching.
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}

// ClientCertMiddleware should be used when running the server in TLS
// mode and mTLS is enabled.
// This is intended for development purposes and must not be used for production
// environments.
func ClientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientCerts := r.TLS.PeerCertificates
		if len(clientCerts) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCerts[0].Raw,
		}
		// Convert the PEM block to a string
		pemBytes := pem.EncodeToMemory(pemBlock)

		// URL encode the PEM string
		encodedPem := url.QueryEscape(string(pemBytes))

		// Transmit the client certificate in a header.
		r.Header.Set(HeaderClientCert, encodedPem)

		next.ServeHTTP(w, r)
	})
}
