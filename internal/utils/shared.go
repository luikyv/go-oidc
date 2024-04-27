package utils

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func NewRedirectErrorFromSession(session models.AuthnSession, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
	return issues.OAuthRedirectError{
		OAuthError: issues.OAuthError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		},
		RedirectUri:  session.RedirectUri,
		ResponseMode: session.ResponseMode,
		State:        session.State,
	}
}

func NewRedirectErrorFromRequest(req models.BaseAuthorizeRequest, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
	return issues.OAuthRedirectError{
		OAuthError: issues.OAuthError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		},
		RedirectUri:  req.RedirectUri,
		ResponseMode: req.ResponseMode,
		State:        req.State,
	}
}
