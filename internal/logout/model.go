package logout

import (
	"net/http"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	callbackIDLength = 30
)

type request struct {
	ClientID string
	goidc.LogoutParameters
}

func newRequest(r *http.Request) request {
	return request{
		ClientID: r.URL.Query().Get("client_id"),
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint:           r.URL.Query().Get("id_token_hint"),
			LogoutHint:            r.URL.Query().Get("logout_hint"),
			PostLogoutRedirectURI: r.URL.Query().Get("post_logout_redirect_uri"),
			State:                 r.URL.Query().Get("state"),
			UILocales:             r.URL.Query().Get("ui_locales"),
		},
	}
}

func newFormRequest(r *http.Request) request {
	return request{
		ClientID: r.PostFormValue("client_id"),
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint:           r.PostFormValue("id_token_hint"),
			LogoutHint:            r.PostFormValue("logout_hint"),
			PostLogoutRedirectURI: r.PostFormValue("post_logout_redirect_uri"),
			State:                 r.PostFormValue("state"),
			UILocales:             r.PostFormValue("ui_locales"),
		},
	}
}
