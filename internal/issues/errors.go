package issues

import (
	"errors"
	"fmt"

	"github.com/luikymagno/auth-server/internal/unit/constants"
)

var ErrorEntityNotFound error = errors.New("entity not found")
var ErrorEntityAlreadyExists error = errors.New("entity already exists")

type OAuthError interface {
	GetCode() constants.ErrorCode
	Error() string
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

type OAuthBaseError struct {
	Inner            error               // It can be used to wrap errors.
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func (err OAuthBaseError) GetCode() constants.ErrorCode {
	return err.ErrorCode
}

func (err OAuthBaseError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (e OAuthBaseError) Unwrap() error {
	return e.Inner
}

type OAuthRedirectError struct {
	OAuthBaseError
	ClientId     string
	RedirectUri  string
	ResponseMode constants.ResponseMode
	State        string
}

func NewOAuthRedirectError(
	errorCode constants.ErrorCode,
	errorDescription string,
	clientId string,
	redirectUri string,
	responseMode constants.ResponseMode,
	state string,
) OAuthRedirectError {
	return OAuthRedirectError{
		OAuthBaseError: OAuthBaseError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		},
		ClientId:     clientId,
		RedirectUri:  redirectUri,
		ResponseMode: responseMode,
		State:        state,
	}
}
