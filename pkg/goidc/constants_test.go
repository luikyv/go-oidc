package goidc_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/luikyv/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
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
				assert.Equal(t, testCase.superShouldContainSub, testCase.superResponseType.Contains(testCase.subResponseType))
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
				assert.Equal(t, testCase.isImplicit, testCase.responseType.IsImplicit())
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

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.expectedResponseMode, testCase.responseType.DefaultResponseMode(testCase.isJARM))
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

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.isJARM, testCase.responseMode.IsJARM())
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

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.isQuery, testCase.responseMode.IsQuery())
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

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, testCase.statusCode, testCase.errorCode.StatusCode())
			},
		)
	}
}
