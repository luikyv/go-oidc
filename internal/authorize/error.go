package authorize

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type RedirectionError struct {
	ErrorCode        oidc.ErrorCode
	ErrorDescription string
	goidc.AuthorizationParameters
}

func (err RedirectionError) Code() oidc.ErrorCode {
	return err.ErrorCode
}

func (err RedirectionError) Error() string {
	return err.ErrorDescription
}

func newRedirectionError(
	code oidc.ErrorCode,
	description string,
	params goidc.AuthorizationParameters,
) oidc.Error {
	return RedirectionError{
		ErrorCode:               code,
		ErrorDescription:        description,
		AuthorizationParameters: params,
	}
}
