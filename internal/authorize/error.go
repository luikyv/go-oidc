package authorize

import (
	"fmt"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type redirectionError struct {
	code    goidc.ErrorCode
	desc    string
	wrapped error
	goidc.AuthorizationParameters
}

func (err redirectionError) Error() string {
	return fmt.Sprintf("%s %s", err.code, err.desc)
}

func (err redirectionError) Unwrap() error {
	return err.wrapped
}

func newRedirectionError(
	code goidc.ErrorCode,
	desc string,
	params goidc.AuthorizationParameters,
) error {
	return redirectionError{
		code:                    code,
		desc:                    desc,
		AuthorizationParameters: params,
	}
}

func redirectionErrorf(
	code goidc.ErrorCode,
	desc string,
	params goidc.AuthorizationParameters,
	err error,
) error {
	return redirectionError{
		code:                    code,
		desc:                    desc,
		AuthorizationParameters: params,
		wrapped:                 err,
	}
}
