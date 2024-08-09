package oidc

import "net/http"

type ErrorCode string

const (
	ErrorCodeAccessDenied                ErrorCode = "access_denied"
	ErrorCodeInvalidClient               ErrorCode = "invalid_client"
	ErrorCodeInvalidGrant                ErrorCode = "invalid_grant"
	ErrorCodeInvalidRequest              ErrorCode = "invalid_request"
	ErrorCodeUnauthorizedClient          ErrorCode = "unauthorized_client"
	ErrorCodeInvalidScope                ErrorCode = "invalid_scope"
	ErrorCodeInvalidAuthorizationDetails ErrorCode = "invalid_authorization_details"
	ErrorCodeUnsupportedGrantType        ErrorCode = "unsupported_grant_type"
	ErrorCodeInvalidResquestObject       ErrorCode = "invalid_request_object"
	ErrorCodeInvalidToken                ErrorCode = "invalid_token"
	ErrorCodeInternalError               ErrorCode = "internal_error"
)

func (ec ErrorCode) StatusCode() int {
	switch ec {
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

type Error interface {
	Code() ErrorCode
	Error() string
}

type baseError struct {
	ErrorCode        ErrorCode `json:"error"`
	ErrorDescription string    `json:"error_description"`
}

func (err baseError) Code() ErrorCode {
	return err.ErrorCode
}

func (err baseError) Error() string {
	return err.ErrorDescription
}

func NewError(code ErrorCode, description string) Error {
	return baseError{
		ErrorCode:        code,
		ErrorDescription: description,
	}
}
