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
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description"`
	wrapped     error
}

func NewError(code ErrorCode, desc string) Error {
	return Error{
		Code:        code,
		Description: desc,
	}
}

func (err Error) Error() string {
	if err.wrapped == nil {
		return fmt.Sprintf("%s %s", err.Code, err.Description)
	}

	return fmt.Sprintf("%s %s: %v", err.Code, err.Description, err.wrapped)
}

func (err Error) Unwrap() error {
	return err.wrapped
}

func Errorf(code ErrorCode, desc string, err error) Error {
	return Error{
		Code:        code,
		Description: desc,
		wrapped:     err,
	}
}
