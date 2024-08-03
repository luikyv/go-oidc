package token

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Handler(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newTokenRequest(ctx.Request())
		tokenResp, err := HandleTokenCreation(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(tokenResp, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}

}

func HandlerIntrospect(config *oidc.Configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.NewContext(*config, r, w)

		req := newTokenIntrospectionRequest(ctx.Request())
		tokenInfo, err := introspect(ctx, req)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(tokenInfo, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
	}
}

type tokenRequest struct {
	GrantType         goidc.GrantType
	Scopes            string
	AuthorizationCode string
	RedirectURI       string
	RefreshToken      string
	CodeVerifier      string
	authn.ClientAuthnRequest
}

func newTokenRequest(req *http.Request) tokenRequest {
	return tokenRequest{
		ClientAuthnRequest: authn.NewClientAuthnRequest(req),
		GrantType:          goidc.GrantType(req.PostFormValue("grant_type")),
		Scopes:             req.PostFormValue("scope"),
		AuthorizationCode:  req.PostFormValue("code"),
		RedirectURI:        req.PostFormValue("redirect_uri"),
		RefreshToken:       req.PostFormValue("refresh_token"),
		CodeVerifier:       req.PostFormValue("code_verifier"),
	}
}

type tokenResponse struct {
	AccessToken          string                      `json:"access_token"`
	IDToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int                         `json:"expires_in"`
	TokenType            goidc.TokenType             `json:"token_type"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
}
