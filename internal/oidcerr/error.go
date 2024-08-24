package oidcerr

import (
	"fmt"
	"net/http"
)

type Code string

const (
	CodeAccessDenied                Code = "access_denied"
	CodeInvalidClient               Code = "invalid_client"
	CodeInvalidGrant                Code = "invalid_grant"
	CodeInvalidRequest              Code = "invalid_request"
	CodeUnauthorizedClient          Code = "unauthorized_client"
	CodeInvalidScope                Code = "invalid_scope"
	CodeInvalidAuthorizationDetails Code = "invalid_authorization_details"
	CodeUnsupportedGrantType        Code = "unsupported_grant_type"
	CodeInvalidResquestObject       Code = "invalid_request_object"
	CodeInvalidToken                Code = "invalid_token"
	CodeInternalError               Code = "internal_error"
	CodeInvalidTarget               Code = "invalid_target"
	CodeInvalidRedirectURI          Code = "invalid_redirect_uri"
	CodeInvalidClientMetadata       Code = "invalid_client_metadata"
)

func (c Code) StatusCode() int {
	switch c {
	case CodeAccessDenied:
		return http.StatusForbidden
	case CodeInvalidClient, CodeInvalidToken, CodeUnauthorizedClient:
		return http.StatusUnauthorized
	case CodeInternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

type Error struct {
	Code        Code   `json:"error"`
	Description string `json:"error_description"`
	wrapped     error
}

func New(code Code, desc string) Error {
	return Error{
		Code:        code,
		Description: desc,
	}
}

func (err Error) Error() string {
	return fmt.Sprintf("%s %s", err.Code, err.Description)
}

func (err Error) Unwrap() error {
	return err.wrapped
}

func Errorf(code Code, desc string, err error) Error {
	return Error{
		Code:        code,
		Description: desc,
		wrapped:     err,
	}
}
