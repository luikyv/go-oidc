package authorize

import (
	"encoding/json"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type oidcErrorAlias = goidc.Error

type redirectionError struct {
	oidcErrorAlias
	goidc.AuthorizationParameters
}

func (err redirectionError) MarshalJSON() ([]byte, error) {
	return json.Marshal(err.oidcErrorAlias)
}

func (err redirectionError) Unwrap() error {
	return err.oidcErrorAlias
}

func newRedirectionError(
	code goidc.ErrorCode,
	desc string,
	params goidc.AuthorizationParameters,
) error {
	return redirectionError{
		oidcErrorAlias:          goidc.NewError(code, desc),
		AuthorizationParameters: params,
	}
}

func wrapRedirectionError(
	code goidc.ErrorCode,
	desc string,
	params goidc.AuthorizationParameters,
	err error,
) error {
	return redirectionError{
		oidcErrorAlias:          goidc.WrapError(code, desc, err),
		AuthorizationParameters: params,
	}
}
