package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err := RunFAPI2OpenIDProvider()
	if err != nil {
		panic(err.Error())
	}
}
