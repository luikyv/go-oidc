package goidc_test

import (
	"fmt"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestGenerateRandomString_ShouldGenerateRandomStrings(t *testing.T) {
	randString1 := goidc.GenerateRandomString(10, 10)
	randString2 := goidc.GenerateRandomString(10, 10)
	if randString1 == randString2 {
		t.Errorf("%s and %s should be different", randString1, randString2)
	}
}

func TestGenerateRandomString_WithDifferentLengths(t *testing.T) {
	var lengthRanges = []struct {
		minLength int
		maxLength int
	}{
		{10, 15},
		{20, 30},
		{10, 10},
	}

	for _, lengthRange := range lengthRanges {
		t.Run(
			fmt.Sprintf("minLength:%v,maxLength:%v", lengthRange.minLength, lengthRange.maxLength),
			func(t *testing.T) {

				randString := goidc.GenerateRandomString(lengthRange.minLength, lengthRange.maxLength)
				if len(randString) < lengthRange.minLength || len(randString) > lengthRange.maxLength {
					t.Errorf("random string %s has length %v", randString, len(randString))
				}

			},
		)
	}
}

func TestGenerateCallbackID(t *testing.T) {
	callbackID := goidc.GenerateCallbackID()
	if len(callbackID) != goidc.CallbackIDLength {
		t.Errorf("callback ID: %s has not %v characters", callbackID, goidc.CallbackIDLength)
	}
}

func TestGenerateAuthorizationCode(t *testing.T) {
	authzCode := goidc.GenerateAuthorizationCode()
	if len(authzCode) != goidc.AuthorizationCodeLength {
		t.Errorf("authorization code: %s has not %d characters", authzCode, goidc.AuthorizationCodeLength)
	}
}

func TestContainsAll(t *testing.T) {
	if !goidc.ContainsAll([]string{"a", "b", "c"}, "a", "b") {
		t.Errorf("%v should contain %v", []string{"a", "b", "c"}, []string{"a", "b"})
	}

	if !goidc.ContainsAll([]int{1, 2}, 1, 2) {
		t.Errorf("%v should contain %v", []int{1, 2}, []int{1, 2})
	}

	if goidc.ContainsAll([]int{1}, 1, 2) {
		t.Errorf("%v should not contain %v", []int{1}, []int{1, 2})
	}
}

func TestContainsAllScopes(t *testing.T) {
	testCases := []struct {
		scopeSuperSet    string
		scopeSubSet      string
		shouldContainAll bool
	}{
		{"scope1 scope2 scope3", "scope1", true},
		{"scope1 scope2 scope3", "scope2", true},
		{"scope1 scope2 scope3", "scope3", true},
		{"scope1", "scope1", true},
		{"scope1 scope2 scope3", "scope1 scope3", true},
		{"scope1 scope2 scope3", "scope1 scope2 scope3", true},
		{"scope1 scope2 scope3", "scope1 ", false},
		{"scope1 scope2 scope3", "scope4", false},
		{"scope1 scope2 scope3", "scope1 scope34 scope2", false},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i+1), func(t *testing.T) {
			if goidc.ContainsAllScopes(testCase.scopeSuperSet, testCase.scopeSubSet) != testCase.shouldContainAll {
				t.Error(testCase)
			}
		})
	}
}
