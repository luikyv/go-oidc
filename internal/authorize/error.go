package authorize

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type redirectionError struct {
	ErrorCode        oidc.ErrorCode
	ErrorDescription string
	goidc.AuthorizationParameters
}

func (err redirectionError) Code() oidc.ErrorCode {
	return err.ErrorCode
}

func (err redirectionError) Error() string {
	return err.ErrorDescription
}

func newRedirectionError(
	code oidc.ErrorCode,
	description string,
	params goidc.AuthorizationParameters,
) oidc.Error {
	return redirectionError{
		ErrorCode:               code,
		ErrorDescription:        description,
		AuthorizationParameters: params,
	}
}
