package unit

import (
	"fmt"
	"testing"

	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestGenerateRandomStringGeneratesRandomStrings(t *testing.T) {
	randString1 := GenerateRandomString(10, 10)
	randString2 := GenerateRandomString(10, 10)
	if randString1 == randString2 {
		t.Errorf("%s and %s should be different", randString1, randString2)
	}
}

func TestGenerateRandomStringWithDifferentLengths(t *testing.T) {
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

				randString := GenerateRandomString(lengthRange.minLength, lengthRange.maxLength)
				if len(randString) < lengthRange.minLength || len(randString) > lengthRange.maxLength {
					t.Errorf("Random string %s has length %v", randString, len(randString))
				}

			},
		)
	}
}

func TestGenerateCallbackIdRightLength(t *testing.T) {
	callbackId := GenerateCallbackId()
	if len(callbackId) != constants.CallbackIdLength {
		t.Errorf("Callback ID: %s has not %v characters", callbackId, constants.CallbackIdLength)
	}
}

func TestGenerateAuthorizationCodeRightLength(t *testing.T) {
	authzCode := GenerateAuthorizationCode()
	if len(authzCode) != constants.AuthorizationCodeLength {
		t.Errorf("Authorization code: %s has not %v characters", authzCode, constants.AuthorizationCodeLength)
	}
}

func TestGetUrlWithParams(t *testing.T) {
	testCases := []struct {
		Url                      string
		params                   map[string]string
		ExpectedParameterizedUrl string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example?param1=value1"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example?param1=value1&param2=value2"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Url, func(t *testing.T) {
			parameterizedUrl := GetUrlWithParams(testCase.Url, testCase.params)

			if parameterizedUrl != testCase.ExpectedParameterizedUrl {
				t.Errorf("%s is different from %s", parameterizedUrl, testCase.ExpectedParameterizedUrl)
			}
		})
	}

}

func TestContains(t *testing.T) {
	if !Contains([]string{"a", "b", "c"}, []string{"a", "b"}) {
		t.Errorf("%v should contain %v", []string{"a", "b", "c"}, []string{"a", "b"})
	}

	if !Contains([]int{1, 2}, []int{1, 2}) {
		t.Errorf("%v should contain %v", []int{1, 2}, []int{1, 2})
	}

	if Contains([]int{1}, []int{1, 2}) {
		t.Errorf("%v should not contain %v", []int{1}, []int{1, 2})
	}
}

func TestFindFirst(t *testing.T) {
	firstString, found := FindFirst([]string{"a", "b", "c"}, func(s string) bool {
		return s == "b"
	})
	if !found || firstString != "b" {
		t.Errorf("the element found was: %v", firstString)
	}

	firstInt, found := FindFirst([]int{1, 2, 3}, func(i int) bool {
		return i == 2
	})
	if !found || firstInt != 2 {
		t.Errorf("the element found was: %v", firstInt)
	}

	_, found = FindFirst([]int{1, 2, 3}, func(i int) bool {
		return i == 4
	})
	if found {
		t.Error("no element should be found")
	}
}
