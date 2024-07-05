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
		{goidc.ResponseTypeCode, goidc.ResponseTypeCode, true},
		{goidc.ResponseTypeCodeAndIDToken, goidc.ResponseTypeCode, true},
		{goidc.ResponseTypeCodeAndIDToken, goidc.ResponseTypeIDToken, true},
		{goidc.ResponseTypeCodeAndIDTokenAndToken, goidc.ResponseTypeIDToken, true},
		{goidc.ResponseTypeCode, goidc.ResponseTypeIDToken, false},
		{goidc.ResponseTypeCodeAndIDToken, goidc.ResponseTypeToken, false},
		{goidc.ResponseTypeCode, goidc.ResponseTypeToken, false},
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
		{goidc.ResponseTypeCode, false},
		{goidc.ResponseTypeIDToken, true},
		{goidc.ResponseTypeToken, true},
		{goidc.ResponseTypeCodeAndIDToken, true},
		{goidc.ResponseTypeCodeAndToken, true},
		{goidc.ResponseTypeIDTokenAndToken, true},
		{goidc.ResponseTypeCodeAndIDTokenAndToken, true},
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
		{goidc.ResponseTypeCode, false, goidc.ResponseModeQuery},
		{goidc.ResponseTypeIDToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeCodeAndIDToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeCodeAndToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeIDTokenAndToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeCodeAndIDTokenAndToken, false, goidc.ResponseModeFragment},
		{goidc.ResponseTypeCode, true, goidc.ResponseModeQueryJWT},
		{goidc.ResponseTypeIDToken, true, goidc.ResponseModeFragmentJWT},
		{goidc.ResponseTypeToken, true, goidc.ResponseModeFragmentJWT},
		{goidc.ResponseTypeCodeAndIDToken, true, goidc.ResponseModeFragmentJWT},
		{goidc.ResponseTypeCodeAndToken, true, goidc.ResponseModeFragmentJWT},
		{goidc.ResponseTypeIDTokenAndToken, true, goidc.ResponseModeFragmentJWT},
		{goidc.ResponseTypeCodeAndIDTokenAndToken, true, goidc.ResponseModeFragmentJWT},
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
		{goidc.ResponseModeQuery, false},
		{goidc.ResponseModeFragment, false},
		{goidc.ResponseModeFormPost, false},
		{goidc.ResponseModeQueryJWT, true},
		{goidc.ResponseModeFragmentJWT, true},
		{goidc.ResponseModeFormPostJWT, true},
		{goidc.ResponseModeJWT, true},
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
		{goidc.ResponseModeQuery, true},
		{goidc.ResponseModeFragment, false},
		{goidc.ResponseModeFormPost, false},
		{goidc.ResponseModeQueryJWT, true},
		{goidc.ResponseModeFragmentJWT, false},
		{goidc.ResponseModeFormPostJWT, false},
		{goidc.ResponseModeJWT, false},
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
		{goidc.ErrorCodeAccessDenied, http.StatusForbidden},
		{goidc.ErrorCodeInvalidClient, http.StatusUnauthorized},
		{goidc.ErrorCodeInvalidGrant, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidRequest, http.StatusBadRequest},
		{goidc.ErrorCodeUnauthorizedClient, http.StatusUnauthorized},
		{goidc.ErrorCodeInvalidScope, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidAuthorizationDetails, http.StatusBadRequest},
		{goidc.ErrorCodeUnsupportedGrantType, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidResquestObject, http.StatusBadRequest},
		{goidc.ErrorCodeInvalidToken, http.StatusUnauthorized},
		{goidc.ErrorCodeInternalError, http.StatusInternalServerError},
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
