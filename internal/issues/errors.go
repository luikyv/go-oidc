package issues

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type EntityNotFoundError struct {
	Id string
}

func (err EntityNotFoundError) Error() string {
	return "Could not find entity with id: " + err.Id
}

type EntityAlreadyExistsError struct {
	Id string
}

func (err EntityAlreadyExistsError) Error() string {
	return "entity with id: " + err.Id + " already exists"
}

type OAuthError interface {
	BindErrorToResponse(*gin.Context)
}

type JsonError struct {
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func (err JsonError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (err JsonError) BindErrorToResponse(requestContext *gin.Context) {
	requestContext.JSON(constants.ErrorCodeToStatusCode[err.ErrorCode], gin.H{
		"error":             err.ErrorCode,
		"error_description": err.ErrorDescription,
	})
}

type RedirectError struct {
	ErrorCode        constants.ErrorCode
	ErrorDescription string
	RedirectUri      string
	State            string
}

func (err RedirectError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (err RedirectError) BindErrorToResponse(requestContext *gin.Context) {
	errorParams := make(map[string]string, 3)
	errorParams["error"] = "access_denied"
	errorParams["error_description"] = "access denied"
	if err.State != "" {
		errorParams["state"] = err.State
	}

	requestContext.Redirect(http.StatusFound, unit.GetUrlWithQueryParams(err.RedirectUri, errorParams))
}
