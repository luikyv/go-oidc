package constants_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/luikymagno/auth-server/internal/constants"
)

func TestResponseTypeContains(t *testing.T) {
	var testCases = []struct {
		superResponseType     constants.ResponseType
		subResponseType       constants.ResponseType
		superShouldContainSub bool
	}{
		{constants.CodeResponse, constants.CodeResponse, true},
		{constants.CodeAndIdTokenResponse, constants.CodeResponse, true},
		{constants.CodeAndIdTokenResponse, constants.IdTokenResponse, true},
		{constants.CodeAndIdTokenAndTokenResponse, constants.IdTokenResponse, true},
		{constants.CodeResponse, constants.IdTokenResponse, false},
		{constants.CodeAndIdTokenResponse, constants.TokenResponse, false},
		{constants.CodeResponse, constants.TokenResponse, false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s should contain %s? %t", testCase.superResponseType, testCase.subResponseType, testCase.superShouldContainSub),
			func(t *testing.T) {
				if testCase.superResponseType.Contains(testCase.subResponseType) != testCase.superShouldContainSub {
					t.Error(testCase)
					return
				}
			},
		)
	}
}

func TestResponseTypeIsImplicit(t *testing.T) {
	var testCases = []struct {
		responseType constants.ResponseType
		isImplicit   bool
	}{
		{constants.CodeResponse, false},
		{constants.IdTokenResponse, true},
		{constants.TokenResponse, true},
		{constants.CodeAndIdTokenResponse, true},
		{constants.CodeAndTokenResponse, true},
		{constants.IdTokenAndTokenResponse, true},
		{constants.CodeAndIdTokenAndTokenResponse, true},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s is implicit? %t", testCase.responseType, testCase.isImplicit),
			func(t *testing.T) {
				if testCase.responseType.IsImplicit() != testCase.isImplicit {
					t.Error(testCase)
					return
				}
			},
		)
	}
}

func TestGetDefaultResponseMode(t *testing.T) {
	var testCases = []struct {
		responseType         constants.ResponseType
		isJarm               bool
		expectedResponseMode constants.ResponseMode
	}{
		{constants.CodeResponse, false, constants.QueryResponseMode},
		{constants.IdTokenResponse, false, constants.FragmentResponseMode},
		{constants.TokenResponse, false, constants.FragmentResponseMode},
		{constants.CodeAndIdTokenResponse, false, constants.FragmentResponseMode},
		{constants.CodeAndTokenResponse, false, constants.FragmentResponseMode},
		{constants.IdTokenAndTokenResponse, false, constants.FragmentResponseMode},
		{constants.CodeAndIdTokenAndTokenResponse, false, constants.FragmentResponseMode},
		{constants.CodeResponse, true, constants.QueryJwtResponseMode},
		{constants.IdTokenResponse, true, constants.FragmentJwtResponseMode},
		{constants.TokenResponse, true, constants.FragmentJwtResponseMode},
		{constants.CodeAndIdTokenResponse, true, constants.FragmentJwtResponseMode},
		{constants.CodeAndTokenResponse, true, constants.FragmentJwtResponseMode},
		{constants.IdTokenAndTokenResponse, true, constants.FragmentJwtResponseMode},
		{constants.CodeAndIdTokenAndTokenResponse, true, constants.FragmentJwtResponseMode},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("the default response mode for %s should be %s. jarm? %t", testCase.responseType, testCase.expectedResponseMode, testCase.isJarm),
			func(t *testing.T) {
				if testCase.responseType.GetDefaultResponseMode(testCase.isJarm) != testCase.expectedResponseMode {
					t.Error(testCase)
				}
			},
		)
	}
}

func TestResponseModeIsJarm(t *testing.T) {
	var testCases = []struct {
		responseMode constants.ResponseMode
		isJarm       bool
	}{
		{constants.QueryResponseMode, false},
		{constants.FragmentResponseMode, false},
		{constants.FormPostResponseMode, false},
		{constants.QueryJwtResponseMode, true},
		{constants.FragmentJwtResponseMode, true},
		{constants.FormPostJwtResponseMode, true},
		{constants.JwtResponseMode, true},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s is JARM? %t", testCase.responseMode, testCase.isJarm),
			func(t *testing.T) {
				if testCase.responseMode.IsJarm() != testCase.isJarm {
					t.Error(testCase)
					return
				}
			},
		)
	}
}

func TestResponseModeIsQuery(t *testing.T) {
	var testCases = []struct {
		responseMode constants.ResponseMode
		isQuery      bool
	}{
		{constants.QueryResponseMode, true},
		{constants.FragmentResponseMode, false},
		{constants.FormPostResponseMode, false},
		{constants.QueryJwtResponseMode, true},
		{constants.FragmentJwtResponseMode, false},
		{constants.FormPostJwtResponseMode, false},
		{constants.JwtResponseMode, false},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s is query? %t", testCase.responseMode, testCase.isQuery),
			func(t *testing.T) {
				if testCase.responseMode.IsQuery() != testCase.isQuery {
					t.Error(testCase)
					return
				}
			},
		)
	}
}

func TestGetStatusCodeFromErrorCode(t *testing.T) {
	var testCases = []struct {
		errorCode  constants.ErrorCode
		statusCode int
	}{
		{constants.AccessDenied, http.StatusForbidden},
		{constants.InvalidClient, http.StatusUnauthorized},
		{constants.InvalidGrant, http.StatusBadRequest},
		{constants.InvalidRequest, http.StatusBadRequest},
		{constants.UnauthorizedClient, http.StatusUnauthorized},
		{constants.InvalidScope, http.StatusBadRequest},
		{constants.UnsupportedGrantType, http.StatusBadRequest},
		{constants.InvalidResquestObject, http.StatusBadRequest},
		{constants.InvalidToken, http.StatusUnauthorized},
		{constants.InternalError, http.StatusInternalServerError},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s should correspond to %d status code", testCase.errorCode, testCase.statusCode),
			func(t *testing.T) {
				if testCase.errorCode.GetStatusCode() != testCase.statusCode {
					t.Error(testCase)
					return
				}
			},
		)
	}
}
