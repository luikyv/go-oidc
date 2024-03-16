package issues

import (
	"fmt"

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

type JsonError struct {
	ErrorCode        constants.ErrorCode `json:"error"`
	ErrorDescription string              `json:"error_description"`
}

func (err JsonError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

func (err JsonError) GetStatusCode() int {
	return constants.ErrorCodeToStatusCode[err.ErrorCode]
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
