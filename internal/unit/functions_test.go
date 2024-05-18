package unit_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
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

func TestGetUrlWithQueryParams(t *testing.T) {
	testCases := []struct {
		Url                      string
		params                   map[string]string
		ExpectedParameterizedUrl string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example?param1=value1"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example?param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			parameterizedUrl := unit.GetUrlWithQueryParams(testCase.Url, testCase.params)

			if parameterizedUrl != testCase.ExpectedParameterizedUrl {
				t.Errorf("%s is different from %s", parameterizedUrl, testCase.ExpectedParameterizedUrl)
			}
		})
	}

}

func TestGetUrlWithFragmentParams(t *testing.T) {
	testCases := []struct {
		Url                      string
		params                   map[string]string
		ExpectedParameterizedUrl string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example#param1=value1"},
		{"http://example#param=value", map[string]string{"param1": "value1"}, "http://example#param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example#param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			parameterizedUrl := unit.GetUrlWithFragmentParams(testCase.Url, testCase.params)

			if parameterizedUrl != testCase.ExpectedParameterizedUrl {
				t.Errorf("%s is different from %s", parameterizedUrl, testCase.ExpectedParameterizedUrl)
			}
		})
	}

}

func TestIsPkceValid(t *testing.T) {
	testCases := []struct {
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod constants.CodeChallengeMethod
		isValid             bool
	}{
		{"4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", constants.SHA256CodeChallengeMethod, true},
		{"42d92ec716da149b8c0a553d5cbbdc5fd474625cdffe7335d643105b", "yQ0Wg2MXS83nBOaS3yit-n-xEaEw5LQ8TlhtX_2NkLw", constants.SHA256CodeChallengeMethod, true},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", constants.SHA256CodeChallengeMethod, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", constants.SHA256CodeChallengeMethod, false},
		{"", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", constants.SHA256CodeChallengeMethod, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "", constants.SHA256CodeChallengeMethod, false},
		{"random_string", "random_string", constants.PlainCodeChallengeMethod, true},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			isValid := unit.IsPkceValid(testCase.codeVerifier, testCase.codeChallenge, testCase.codeChallengeMethod)
			if testCase.isValid != isValid {
				t.Error("error validating PKCE")
			}
		})
	}
}

func TestContainsAll(t *testing.T) {
	if !unit.ContainsAll([]string{"a", "b", "c"}, []string{"a", "b"}) {
		t.Errorf("%v should contain %v", []string{"a", "b", "c"}, []string{"a", "b"})
	}

	if !unit.ContainsAll([]int{1, 2}, []int{1, 2}) {
		t.Errorf("%v should contain %v", []int{1, 2}, []int{1, 2})
	}

	if unit.ContainsAll([]int{1}, []int{1, 2}) {
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

func TestGenerateJwkThumbprint(t *testing.T) {
	dpopSigningAlgorithms := []jose.SignatureAlgorithm{jose.ES256}
	testCases := []struct {
		DpopJwt            string
		ExpectedThumbprint string
	}{
		{
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			jkt := unit.GenerateJwkThumbprint(testCase.DpopJwt, dpopSigningAlgorithms)
			if jkt != testCase.ExpectedThumbprint {
				t.Errorf("invalid thumbprint. expected: %s - actual: %s", testCase.ExpectedThumbprint, jkt)
			}
		})
	}
}
