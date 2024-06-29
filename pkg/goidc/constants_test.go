package goidc_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestResponseType_Contains_HappyPath(t *testing.T) {
	var testCases = []struct {
		superResponseType     goidc.ResponseType
		subResponseType       goidc.ResponseType
		superShouldContainSub bool
	}{
		{goidc.CodeResponse, goidc.CodeResponse, true},
		{goidc.CodeAndIDTokenResponse, goidc.CodeResponse, true},
		{goidc.CodeAndIDTokenResponse, goidc.IDTokenResponse, true},
		{goidc.CodeAndIDTokenAndTokenResponse, goidc.IDTokenResponse, true},
		{goidc.CodeResponse, goidc.IDTokenResponse, false},
		{goidc.CodeAndIDTokenResponse, goidc.TokenResponse, false},
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

func TestResponseType_IsImplicit_HappyPath(t *testing.T) {
	var testCases = []struct {
		responseType goidc.ResponseType
		isImplicit   bool
	}{
		{goidc.CodeResponse, false},
		{goidc.IDTokenResponse, true},
		{goidc.TokenResponse, true},
		{goidc.CodeAndIDTokenResponse, true},
		{goidc.CodeAndTokenResponse, true},
		{goidc.IDTokenAndTokenResponse, true},
		{goidc.CodeAndIDTokenAndTokenResponse, true},
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

func TestResponseType_GetDefaultResponseMode_HappyPath(t *testing.T) {
	var testCases = []struct {
		responseType         goidc.ResponseType
		isJARM               bool
		expectedResponseMode goidc.ResponseMode
	}{
		{goidc.CodeResponse, false, goidc.QueryResponseMode},
		{goidc.IDTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.TokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndIDTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.IDTokenAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeAndIDTokenAndTokenResponse, false, goidc.FragmentResponseMode},
		{goidc.CodeResponse, true, goidc.QueryJWTResponseMode},
		{goidc.IDTokenResponse, true, goidc.FragmentJWTResponseMode},
		{goidc.TokenResponse, true, goidc.FragmentJWTResponseMode},
		{goidc.CodeAndIDTokenResponse, true, goidc.FragmentJWTResponseMode},
		{goidc.CodeAndTokenResponse, true, goidc.FragmentJWTResponseMode},
		{goidc.IDTokenAndTokenResponse, true, goidc.FragmentJWTResponseMode},
		{goidc.CodeAndIDTokenAndTokenResponse, true, goidc.FragmentJWTResponseMode},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("the default response mode for %s should be %s. jarm? %t", testCase.responseType, testCase.expectedResponseMode, testCase.isJARM),
			func(t *testing.T) {
				if testCase.responseType.GetDefaultResponseMode(testCase.isJARM) != testCase.expectedResponseMode {
					t.Error(testCase)
				}
			},
		)
	}
}

func TestResponseMode_IsJARM_HappyPath(t *testing.T) {
	var testCases = []struct {
		responseMode goidc.ResponseMode
		isJARM       bool
	}{
		{goidc.QueryResponseMode, false},
		{goidc.FragmentResponseMode, false},
		{goidc.FormPostResponseMode, false},
		{goidc.QueryJWTResponseMode, true},
		{goidc.FragmentJWTResponseMode, true},
		{goidc.FormPostJWTResponseMode, true},
		{goidc.JWTResponseMode, true},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s is JARM? %t", testCase.responseMode, testCase.isJARM),
			func(t *testing.T) {
				if testCase.responseMode.IsJARM() != testCase.isJARM {
					t.Error(testCase)
					return
				}
			},
		)
	}
}

func TestResponseMode_IsQuery_HappyPath(t *testing.T) {
	var testCases = []struct {
		responseMode goidc.ResponseMode
		isQuery      bool
	}{
		{goidc.QueryResponseMode, true},
		{goidc.FragmentResponseMode, false},
		{goidc.FormPostResponseMode, false},
		{goidc.QueryJWTResponseMode, true},
		{goidc.FragmentJWTResponseMode, false},
		{goidc.FormPostJWTResponseMode, false},
		{goidc.JWTResponseMode, false},
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

func TestErrorCode_GetStatusCode_HappyPath(t *testing.T) {
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
