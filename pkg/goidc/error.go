package goidc

import (
	"fmt"
	"net/http"
)

type ErrorCode string

const (
	ErrorCodeAccessDenied           ErrorCode = "access_denied"
	ErrorCodeInvalidClient          ErrorCode = "invalid_client"
	ErrorCodeInvalidGrant           ErrorCode = "invalid_grant"
	ErrorCodeInvalidRequest         ErrorCode = "invalid_request"
	ErrorCodeUnauthorizedClient     ErrorCode = "unauthorized_client"
	ErrorCodeInvalidScope           ErrorCode = "invalid_scope"
	ErrorCodeInvalidAuthDetails     ErrorCode = "invalid_authorization_details"
	ErrorCodeUnsupportedGrantType   ErrorCode = "unsupported_grant_type"
	ErrorCodeInvalidResquestObject  ErrorCode = "invalid_request_object"
	ErrorCodeInvalidToken           ErrorCode = "invalid_token"
	ErrorCodeInternalError          ErrorCode = "internal_error"
	ErrorCodeInvalidTarget          ErrorCode = "invalid_target"
	ErrorCodeInvalidRedirectURI     ErrorCode = "invalid_redirect_uri"
	ErrorCodeInvalidClientMetadata  ErrorCode = "invalid_client_metadata"
	ErrorCodeRequestURINotSupported ErrorCode = "request_uri_not_supported"
	ErrorCodeLoginRequired          ErrorCode = "login_required"
	ErrorCodeAuthPending            ErrorCode = "authorization_pending"
	ErrorCodeSlowDown               ErrorCode = "slow_down"
	ErrorCodeExpiredToken           ErrorCode = "expired_token"
	ErrorCodeMissingUserCode        ErrorCode = "missing_user_code"
	ErrorCodeInvalidUserCode        ErrorCode = "invalid_user_code"
	ErrorCodeInvalidBindingMessage  ErrorCode = "invalid_binding_message"
	ErrorCodeUnknownUserID          ErrorCode = "unknown_user_id"
	ErrorCodeTransactionFailed      ErrorCode = "transaction_failed"
	ErrorCodeExpiredLoginHintToken  ErrorCode = "expired_login_hint_token"
)

func (c ErrorCode) StatusCode() int {
	switch c {
	case ErrorCodeAccessDenied:
		return http.StatusForbidden
	case ErrorCodeInvalidClient, ErrorCodeInvalidToken, ErrorCodeUnauthorizedClient:
		return http.StatusUnauthorized
	case ErrorCodeInternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

type Error struct {
	Code        ErrorCode `json:"error,omitempty"`
	Description string    `json:"error_description,omitempty"`
	statusCode  int       `json:"-"`
	wrapped     error     `json:"-"`
}

func NewError(code ErrorCode, desc string) Error {
	return Error{
		Code:        code,
		Description: desc,
	}
}

func NewErrorWithStatus(code ErrorCode, desc string, status int) Error {
	return Error{
		Code:        code,
		Description: desc,
		statusCode:  status,
	}
}

func (err Error) Error() string {
	if err.wrapped == nil {
		return fmt.Sprintf("%s %s", err.Code, err.Description)
	}

	return fmt.Sprintf("%s %s: %v", err.Code, err.Description, err.wrapped)
}

func (err Error) StatusCode() int {
	if err.statusCode != 0 {
		return err.statusCode
	}

	return err.Code.StatusCode()
}

func (err Error) Unwrap() error {
	return err.wrapped
}

func WrapError(code ErrorCode, desc string, err error) Error {
	return Error{
		Code:        code,
		Description: desc,
		wrapped:     err,
	}
}
