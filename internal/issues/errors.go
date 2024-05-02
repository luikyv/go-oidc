package issues

import (
	"errors"
	"fmt"

	"github.com/luikymagno/auth-server/internal/unit/constants"
)

var ErrorEntityNotFound error = errors.New("entity not found")
var ErrorEntityAlreadyExists error = errors.New("entity already exists")

type OAuthError struct {
	Inner            error               // It can be used to wrap errors.
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func NewOAuthError(code constants.ErrorCode, description string) OAuthError {
	return OAuthError{
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

func NewWrappingOAuthError(err error, code constants.ErrorCode, description string) OAuthError {
	return OAuthError{
		Inner:            err,
		ErrorCode:        code,
		ErrorDescription: description,
	}
}

func (err OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (e OAuthError) Unwrap() error {
	return e.Inner
}

type OAuthRedirectError struct {
	OAuthError
	ClientId     string
	RedirectUri  string
	ResponseMode constants.ResponseMode
	State        string
}

func NewOAuthRedirectErrorFrom(errorCode constants.ErrorCode, errorDescription string, clientId string, redirectUri string, responseMode constants.ResponseMode, state string) OAuthRedirectError {
	return OAuthRedirectError{
		OAuthError:   NewOAuthError(errorCode, errorDescription),
		ClientId:     clientId,
		RedirectUri:  redirectUri,
		ResponseMode: responseMode,
		State:        state,
	}
}
