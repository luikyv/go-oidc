package authorize

import (
	"encoding/json"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type redirectionError struct {
	goidc.AuthorizationParameters
	err goidc.Error
}

func (err redirectionError) Error() string {
	return err.err.Error()
}

func (err redirectionError) Unwrap() error {
	return err.err
}

func (err redirectionError) MarshalJSON() ([]byte, error) {
	return json.Marshal(err.err)
}

func (err redirectionError) Code() goidc.ErrorCode {
	return err.err.Code
}

func (err redirectionError) Description() string {
	return err.err.Description
}

func newRedirectionError(code goidc.ErrorCode, desc string, params goidc.AuthorizationParameters) error {
	return redirectionError{
		err:                     goidc.NewError(code, desc),
		AuthorizationParameters: params,
	}
}

func wrapRedirectionError(code goidc.ErrorCode, desc string, params goidc.AuthorizationParameters, err error) error {
	return redirectionError{
		err:                     goidc.WrapError(code, desc, err),
		AuthorizationParameters: params,
	}
}
