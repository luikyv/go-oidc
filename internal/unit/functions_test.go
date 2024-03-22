package unit_test

import (
	"fmt"
	"testing"

	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestGenerateRandomStringGeneratesRandomStrings(t *testing.T) {
	randString1 := unit.GenerateRandomString(10, 10)
	randString2 := unit.GenerateRandomString(10, 10)
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

				randString := unit.GenerateRandomString(lengthRange.minLength, lengthRange.maxLength)
				if len(randString) < lengthRange.minLength || len(randString) > lengthRange.maxLength {
					t.Errorf("Random string %s has length %v", randString, len(randString))
				}

			},
		)
	}
}

func TestGenerateCallbackIdRightLength(t *testing.T) {
	callbackId := unit.GenerateCallbackId()
	if len(callbackId) != constants.CallbackIdLength {
		t.Errorf("Callback ID: %s has not %v characters", callbackId, constants.CallbackIdLength)
	}
}

func TestGenerateAuthorizationCodeRightLength(t *testing.T) {
	authzCode := unit.GenerateAuthorizationCode()
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
			parameterizedUrl := unit.GetUrlWithParams(testCase.Url, testCase.params)

			if parameterizedUrl != testCase.ExpectedParameterizedUrl {
				t.Errorf("%s is different from %s", parameterizedUrl, testCase.ExpectedParameterizedUrl)
			}
		})
	}

}

func TestContains(t *testing.T) {
	if !unit.Contains([]string{"a", "b", "c"}, []string{"a", "b"}) {
		t.Errorf("%v should contain %v", []string{"a", "b", "c"}, []string{"a", "b"})
	}

	if !unit.Contains([]int{1, 2}, []int{1, 2}) {
		t.Errorf("%v should contain %v", []int{1, 2}, []int{1, 2})
	}

	if unit.Contains([]int{1}, []int{1, 2}) {
		t.Errorf("%v should not contain %v", []int{1}, []int{1, 2})
	}
}

func TestFindFirst(t *testing.T) {
	firstString, found := unit.FindFirst([]string{"a", "b", "c"}, func(s string) bool {
		return s == "b"
	})
	if !found || firstString != "b" {
		t.Errorf("the element found was: %v", firstString)
	}

	firstInt, found := unit.FindFirst([]int{1, 2, 3}, func(i int) bool {
		return i == 2
	})
	if !found || firstInt != 2 {
		t.Errorf("the element found was: %v", firstInt)
	}

	_, found = unit.FindFirst([]int{1, 2, 3}, func(i int) bool {
		return i == 4
	})
	if found {
		t.Error("no element should be found")
	}
}

func TestAll(t *testing.T) {
	ok := unit.All([]string{"a", "b", "c"}, func(s string) bool {
		return s == "b"
	})
	if ok {
		t.Errorf("not all the elements respect the condition")
		return
	}

	ok = unit.All([]int{1, 2, 3}, func(i int) bool {
		return i > 0
	})
	if !ok {
		t.Errorf("all the elements respect the condition")
		return
	}

	ok = unit.All([]int{1, 2, 3}, func(i int) bool {
		return i == 4
	})
	if ok {
		t.Errorf("not all the elements respect the condition")
		return
	}
}
