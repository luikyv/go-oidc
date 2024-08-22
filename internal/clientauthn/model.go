package clientauthn

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Request struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ID            string
	Secret        string
	AssertionType goidc.ClientAssertionType
	Assertion     string
}

func NewRequest(req *http.Request) Request {
	return Request{
		ID:            req.PostFormValue("client_id"),
		Secret:        req.PostFormValue("client_secret"),
		AssertionType: goidc.ClientAssertionType(req.PostFormValue("client_assertion_type")),
		Assertion:     req.PostFormValue("client_assertion"),
	}
}
