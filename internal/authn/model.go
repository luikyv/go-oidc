package authn

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ClientAuthnRequest struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ClientID            string
	ClientSecret        string
	ClientAssertionType goidc.ClientAssertionType
	ClientAssertion     string
}

func NewClientAuthnRequest(req *http.Request) ClientAuthnRequest {
	return ClientAuthnRequest{
		ClientID:            req.PostFormValue("client_id"),
		ClientSecret:        req.PostFormValue("client_secret"),
		ClientAssertionType: goidc.ClientAssertionType(req.PostFormValue("client_assertion_type")),
		ClientAssertion:     req.PostFormValue("client_assertion"),
	}
}
