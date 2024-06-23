package goidc_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestResponseTypeContains(t *testing.T) {
	var testCases = []struct {
		superResponseType     goidc.ResponseType
		subResponseType       goidc.ResponseType
		superShouldContainSub bool
	}{
		{goidc.CodeResponse, goidc.CodeResponse, true},
		{goidc.CodeAndIdTokenResponse, goidc.CodeResponse, true},
		{goidc.CodeAndIdTokenResponse, goidc.IdTokenResponse, true},
		{goidc.CodeAndIdTokenAndTokenResponse, goidc.IdTokenResponse, true},
		{goidc.CodeResponse, goidc.IdTokenResponse, false},
		{goidc.CodeAndIdTokenResponse, goidc.TokenResponse, false},
		{goidc.CodeResponse, goidc.TokenResponse, false},
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
		responseType goidc.ResponseType
		isImplicit   bool
	}{
		{goidc.CodeResponse, false},
		{goidc.IdTokenResponse, true},
		{goidc.TokenResponse, true},
		{goidc.CodeAndIdTokenResponse, true},
		{goidc.CodeAndTokenResponse, true},
		{goidc.IdTokenAndTokenResponse, true},
		{goidc.CodeAndIdTokenAndTokenResponse, true},
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
		responseType         goidc.ResponseType
		isJarm               bool
		expectedResponseMode goidc.ResponseMode
	}{
		{goidc.CodeResponse, false, goidc.QueryResponseMode},
		{goidc.IdTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.TokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndIdTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.IdTokenAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndIdTokenAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeResponse, true, goidc.QueryJwtResponseMode},
		{goidc.IdTokenResponse, true, goidc.FragmentJwtResponseMode},
		{goidc.TokenResponse, true, goidc.FragmentJwtResponseMode},
		{goidc.CodeAndIdTokenResponse, true, goidc.FragmentJwtResponseMode},
		{goidc.CodeAndTokenResponse, true, goidc.FragmentJwtResponseMode},
		{goidc.IdTokenAndTokenResponse, true, goidc.FragmentJwtResponseMode},
		{goidc.CodeAndIdTokenAndTokenResponse, true, goidc.FragmentJwtResponseMode},
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
		responseMode goidc.ResponseMode
		isJarm       bool
	}{
		{goidc.QueryResponseMode, false},
		{goidc.FragmentResponseMode, false},
		{goidc.FormPostResponseMode, false},
		{goidc.QueryJwtResponseMode, true},
		{goidc.FragmentJwtResponseMode, true},
		{goidc.FormPostJwtResponseMode, true},
		{goidc.JwtResponseMode, true},
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
		responseMode goidc.ResponseMode
		isQuery      bool
	}{
		{goidc.QueryResponseMode, true},
		{goidc.FragmentResponseMode, false},
		{goidc.FormPostResponseMode, false},
		{goidc.QueryJwtResponseMode, true},
		{goidc.FragmentJwtResponseMode, false},
		{goidc.FormPostJwtResponseMode, false},
		{goidc.JwtResponseMode, false},
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
		errorCode  goidc.ErrorCode
		statusCode int
	}{
		{goidc.AccessDenied, http.StatusForbidden},
		{goidc.InvalidClient, http.StatusUnauthorized},
		{goidc.InvalidGrant, http.StatusBadRequest},
		{goidc.InvalidRequest, http.StatusBadRequest},
		{goidc.UnauthorizedClient, http.StatusUnauthorized},
		{goidc.InvalidScope, http.StatusBadRequest},
		{goidc.InvalidAuthorizationDetails, http.StatusBadRequest},
		{goidc.UnsupportedGrantType, http.StatusBadRequest},
		{goidc.InvalidResquestObject, http.StatusBadRequest},
		{goidc.InvalidToken, http.StatusUnauthorized},
		{goidc.InternalError, http.StatusInternalServerError},
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
