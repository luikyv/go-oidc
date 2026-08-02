package goidc

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrNotFound signals that a requested entity does not exist.
//
// Custom manager implementations should return this error, or wrap it so that
// errors.Is(err, [ErrNotFound]) is true, when the requested state is missing.
// go-oidc relies on this contract to distinguish missing entities from
// operational failures and to produce the correct protocol behavior.
var ErrNotFound = errors.New("not found")

type ErrorCode string

const (
	ErrorCodeAccessDenied             ErrorCode = "access_denied"
	ErrorCodeInvalidClient            ErrorCode = "invalid_client"
	ErrorCodeInvalidGrant             ErrorCode = "invalid_grant"
	ErrorCodeInvalidRequest           ErrorCode = "invalid_request"
	ErrorCodeInvalidCredentialRequest ErrorCode = "invalid_credential_request" //nolint:gosec
	ErrorCodeUnauthorizedClient       ErrorCode = "unauthorized_client"
	ErrorCodeInvalidScope             ErrorCode = "invalid_scope"
	ErrorCodeInvalidAuthDetails       ErrorCode = "invalid_authorization_details"
	ErrorCodeUnsupportedGrantType     ErrorCode = "unsupported_grant_type"
	ErrorCodeInvalidRequestObject     ErrorCode = "invalid_request_object"
	ErrorCodeInvalidToken             ErrorCode = "invalid_token"
	ErrorCodeUseDPoPNonce             ErrorCode = "use_dpop_nonce"
	ErrorCodeInternalError            ErrorCode = "internal_error"
	ErrorCodeInvalidTarget            ErrorCode = "invalid_target"
	ErrorCodeInvalidRedirectURI       ErrorCode = "invalid_redirect_uri"
	ErrorCodeInvalidClientMetadata    ErrorCode = "invalid_client_metadata"
	ErrorCodeRequestURINotSupported   ErrorCode = "request_uri_not_supported"
	ErrorCodeLoginRequired            ErrorCode = "login_required"
	ErrorCodeAuthPending              ErrorCode = "authorization_pending"
	ErrorCodeSlowDown                 ErrorCode = "slow_down"
	ErrorCodeExpiredToken             ErrorCode = "expired_token"
	ErrorCodeMissingUserCode          ErrorCode = "missing_user_code"
	ErrorCodeInvalidUserCode          ErrorCode = "invalid_user_code"
	ErrorCodeInvalidBindingMessage    ErrorCode = "invalid_binding_message"
	ErrorCodeUnknownUserID            ErrorCode = "unknown_user_id"
	ErrorCodeTransactionFailed        ErrorCode = "transaction_failed"
	ErrorCodeExpiredLoginHintToken    ErrorCode = "expired_login_hint_token"
	ErrorCodeInvalidTrustAnchor       ErrorCode = "invalid_trust_anchor"
	ErrorCodeInvalidTrustChain        ErrorCode = "invalid_trust_chain"
	ErrorCodeInvalidMetadata          ErrorCode = "invalid_metadata"
	// ErrorCodeInvalidTransactionID signals that the transaction_id used to
	// poll the deferred credential endpoint is invalid. See [OIDC4VCI §9.3].
	ErrorCodeInvalidTransactionID ErrorCode = "invalid_transaction_id"
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
	URI         string    `json:"error_uri,omitempty"`
	statusCode  int       `json:"-"`
	wrapped     error     `json:"-"`
}

func NewError(code ErrorCode, desc string) Error {
	return Error{
		Code:        code,
		Description: desc,
	}
}

// Errorf returns an OAuth error with a formatted public description.
// Do not use %w with Errorf, use [WrapError] to preserve an underlying error.
func Errorf(code ErrorCode, format string, args ...any) Error {
	return Error{
		Code:        code,
		Description: fmt.Sprintf(format, args...),
	}
}

func WrapError(code ErrorCode, desc string, err error) Error {
	return Error{
		Code:        code,
		Description: desc,
		wrapped:     err,
	}
}

func (err Error) WithURI(uri string) Error {
	err.URI = uri
	return err
}

func (err Error) WithStatusCode(status int) Error {
	err.statusCode = status
	return err
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
