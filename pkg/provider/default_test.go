package provider

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	validClientCert = `
-----BEGIN CERTIFICATE-----
MIIE2TCCAsGgAwIBAgIUJ6YypiFCch1yfe6Po8AYfI9moOcwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKY2xpZW50X29uZTAeFw0yNDA5MDEyMTAxMDJaFw0yNDEw
MDEyMTAxMDJaMBUxEzARBgNVBAMMCmNsaWVudF9vbmUwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDgDLAH0eM8ETIQ+JNM1U68rObo8O+LHKaNfepnbuLJ
yQn3D4N6909xyqXfA3DsUmC4XhULRna+xrHqXf2dYHZ7j46UMW0C/GSgedO9k+dB
qptcBHs9B6iUTKRRgKBT5IYwqjQGqOODH6UwgaLvgxXkGm5/MM/K/4OOhSse3KO4
84dc6n/6N5FcQGGE6w7AIA9srKFLP0mYUnxQ49hqTwKkaZf975UepODkEOU+T79F
VnOktrGoawQOky60Ne92qCSx3BmLKciuoAZZXmceHDZV8skQlL4e1rFwogBFOhzQ
YxmFjaQ//KS7iFq1OKq/Y9gOh8CMA95Au2es87YyLwg9bjS7d+rHgUW516kdSnOa
/tnPFKqU7a8s8dtymsbSJuPinUjDMWBGUdy5HpIkm1+/rSUCAkjuZfEX7duERawA
WMc2dgawT+/2LmBmj85KyjeUdgYRGBxbUmeOgavy5Lp5oLwETIVCuFcTkWDA9z0N
MSOvDVxVX9Q92fo7vZlHXbZcHOdPpQ431YfE0HFdm9FVTLZZU18r6G+xjjw4Yw/W
nbGQirwEkz8fEzkqfI57jnmY4YglPLlLahD+Jrq04SJbq0V0BIrcpdF9/LfZbboo
8ZlOVGxlstSFAWQdYfXn+jU/XXtMfjcELVTGAzOk4JlEOhg9mxmPD1asXnR0K6kt
aQIDAQABoyEwHzAdBgNVHQ4EFgQUD0XEAshwmMAwoTNzB5QS1/QjAlAwDQYJKoZI
hvcNAQELBQADggIBAAFrqjZ0HJdfTpB4Eocr4pgxyyVbBeL7SEkXZVwlPbH/Z/HG
Dkod62JMxaNYsXpsa6l8W+jxgdwHQj/CclH2J5wfG7VenNyYO362FSmwGHIbTvck
3AEaYFhvFaGtYSQ5CAhaupILeE3y8kI5pDBZV7vtnkaZOhPRtivIe0qsQ/8IRadF
fj2ywUgMBVJpj/0N2L1TtshwnCXbwKt6htvwSBNSuKGIOjXFGVDN2kCx4YBxxYju
SaC/FIQ40lwP+AdsSRvftKI3iowrfippxa9nGO9jLv3kXTxi+ZT9d3j5+XzE1vQZ
/G3hflzgWVNRxCTR+ObfCkkmZp4zX/u2sZTjvrobs+73ONrMYWnkS8NiLd2jq3zA
OIBgbWJYVCAkGtx4XQPHW5Q7xb0UmlG5bfABRUhqhUFipA3O8UhLEEdfsNKqIMvj
mazF1nkKaXkMezKhChXyFUz0Sgvnvx2eqvmkD/eWrv94j7fXr9z3s5ISr1X5ODLb
OnDXZcF33Ir06AD2mWpUdqrwXZ+HS1YzU/Qp+7vzUcILzumeHiCUVIs/dubek/ow
vtjosnK5k5wVUb+rKEoggfie1NMYXUwXOZYz+RAVtkXvM6ZgkyvN9BGnsggv+BYt
e3DdyuB1tAcjNnpQNmLtiO2v1wDsEy9hgf2X7OlYim1MAWDo2gPAkJY+SS9m
-----END CERTIFICATE-----
`
	validPrivateKey = `
-----BEGIN PRIVATE KEY-----
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
cP/CTjtjEGwIWksLJJ/kVT01VzwCa0bk
-----END PRIVATE KEY-----

`
)

func TestDefaultClientCertFunc(t *testing.T) {
	// Given.
	clientCertFunc := defaultClientCertFunc()

	encodeCert := url.QueryEscape(validClientCert)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set(goidc.HeaderClientCert, encodeCert)

	// When.
	cert, err := clientCertFunc(r)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cert == nil {
		t.Error("the client certificate cannot be nil")
	}
}

func TestDefaultClientCertFunc_CertNotInformed(t *testing.T) {
	// Given.
	clientCertFunc := defaultClientCertFunc()

	r := httptest.NewRequest(http.MethodPost, "/", nil)

	// When.
	_, err := clientCertFunc(r)

	// Then.
	if err == nil {
		t.Fatalf("an error should be returned when the certificate is not informed")
	}
}

func TestDefaultClientCertFunc_InvalidFormat(t *testing.T) {
	// Given.
	clientCertFunc := defaultClientCertFunc()

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set(goidc.HeaderClientCert, "invalid_certificate")

	// When.
	_, err := clientCertFunc(r)

	// Then.
	if err == nil {
		t.Fatalf("an error should be returned when an invalid certificate is informed")
	}
}

func TestDefaultClientCertFunc_NotACertificate(t *testing.T) {
	// Given.
	clientCertFunc := defaultClientCertFunc()

	encodePrivateKey := url.QueryEscape(validPrivateKey)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set(goidc.HeaderClientCert, encodePrivateKey)

	// When.
	_, err := clientCertFunc(r)

	// Then.
	if err == nil {
		t.Fatalf("an error should be returned when an invalid certificate is informed")
	}
}
