package authorize

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetURLWithQueryParams(t *testing.T) {
	testCases := []struct {
		URL                      string
		params                   map[string]string
		ExpectedParameterizedURL string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example?param1=value1"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example?param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedParameterizedURL, urlWithQueryParams(testCase.URL, testCase.params))
		})
	}

}

func TestGetURLWithFragmentParams(t *testing.T) {
	testCases := []struct {
		URL                      string
		params                   map[string]string
		ExpectedParameterizedURL string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example#param1=value1"},
		{"http://example", map[string]string{"param1": "https://localhost"}, "http://example#param1=https%3A%2F%2Flocalhost"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value#param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example#param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedParameterizedURL, urlWithFragmentParams(testCase.URL, testCase.params))
		})
	}

}
