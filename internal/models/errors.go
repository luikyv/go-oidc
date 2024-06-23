package models

import (
	"errors"

	"github.com/luikymagno/goidc/pkg/goidc"
)

var ErrorEntityNotFound error = errors.New("entity not found")
var ErrorEntityAlreadyExists error = errors.New("entity already exists")

type OAuthError interface {
	GetCode() goidc.ErrorCode
	Error() string
}

type OAuthBaseError struct {
	Inner            error           // It can be used to wrap errors.
	ErrorCode        goidc.ErrorCode `json:"error"`
	ErrorDescription string          `json:"error_description"`
}

func (err OAuthBaseError) GetCode() goidc.ErrorCode {
	return err.ErrorCode
}

func (err OAuthBaseError) Error() string {
	return err.ErrorDescription
}

func (e OAuthBaseError) Unwrap() error {
	return e.Inner
}

func NewOAuthError(code goidc.ErrorCode, description string) OAuthError {
	return OAuthBaseError{
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

func NewWrappingOAuthError(err error, code goidc.ErrorCode, description string) OAuthError {
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
	errorCode goidc.ErrorCode,
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
