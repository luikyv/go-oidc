package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type resultChannel struct {
	Result any
	Err    goidc.OAuthError
}

type tokenIntrospectionRequest struct {
	authn.ClientAuthnRequest
	Token         string
	TokenTypeHint goidc.TokenTypeHint
}

func newTokenIntrospectionRequest(req *http.Request) tokenIntrospectionRequest {
	return tokenIntrospectionRequest{
		ClientAuthnRequest: authn.NewClientAuthnRequest(req),
		Token:              req.PostFormValue("token"),
		TokenTypeHint:      goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}
