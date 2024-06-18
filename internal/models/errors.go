package models

import (
	"errors"

	"github.com/luikymagno/auth-server/internal/constants"
)

var ErrorEntityNotFound error = errors.New("entity not found")
var ErrorEntityAlreadyExists error = errors.New("entity already exists")

type OAuthError interface {
	GetCode() constants.ErrorCode
	Error() string
}

type OAuthBaseError struct {
	Inner            error               // It can be used to wrap errors.
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func (err OAuthBaseError) GetCode() constants.ErrorCode {
	return err.ErrorCode
}

func (err OAuthBaseError) Error() string {
	return err.ErrorDescription
}

func (e OAuthBaseError) Unwrap() error {
	return e.Inner
}

func NewOAuthError(code constants.ErrorCode, description string) OAuthError {
	return OAuthBaseError{
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

func NewWrappingOAuthError(err error, code constants.ErrorCode, description string) OAuthError {
	return OAuthBaseError{
		Inner:            err,
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

type OAuthRedirectError struct {
	OAuthBaseError
	AuthorizationParameters
}

func NewOAuthRedirectError(
	errorCode constants.ErrorCode,
	errorDescription string,
	params AuthorizationParameters,
) OAuthRedirectError {
	return OAuthRedirectError{
		OAuthBaseError: OAuthBaseError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		},
		AuthorizationParameters: params,
	}
}
