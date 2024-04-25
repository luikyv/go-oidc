package issues

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

var ErrorEntityNotFound error = errors.New("entity not found")
var ErrorEntityAlreadyExists error = errors.New("entity already exists")

type OAuthError interface {
	error
	BindErrorToResponse(*gin.Context)
}

type OAuthBaseError struct {
	Inner            error               // It can be used to wrap errors.
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func (err OAuthBaseError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (e OAuthBaseError) Unwrap() error {
	return e.Inner
}

func (err OAuthBaseError) BindErrorToResponse(requestContext *gin.Context) {
	requestContext.JSON(constants.ErrorCodeToStatusCode[err.ErrorCode], gin.H{
		"error":             err.ErrorCode,
		"error_description": err.ErrorDescription,
	})
}

type OAuthRedirectError struct {
	OAuthBaseError
	RedirectUri string
	State       string
}

func (err OAuthRedirectError) BindErrorToResponse(requestContext *gin.Context) {
	errorParams := map[string]string{
		"error":             string(err.ErrorCode),
		"error_description": err.ErrorDescription,
	}
	if err.State != "" {
		errorParams["state"] = err.State
	}

	requestContext.Redirect(http.StatusFound, unit.GetUrlWithQueryParams(err.RedirectUri, errorParams))
}
