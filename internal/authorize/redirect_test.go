package authorize_test

import (
	"fmt"
	"testing"

	"github.com/luikyv/go-oidc/internal/authorize"
)

func TestGetURLWithQueryParams(t *testing.T) {
	// Given.
	testCases := []struct {
		url      string
		params   map[string]string
		expected string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example?param1=value1"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example?param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				// When.
				got := authorize.URLWithQueryParams(testCase.url, testCase.params)

				// Then.
				if got != testCase.expected {
					t.Errorf("URLWithQueryParams() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}

}

func TestGetURLWithFragmentParams(t *testing.T) {
	// Given.
	testCases := []struct {
		url      string
		params   map[string]string
		expected string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example#param1=value1"},
		{"http://example", map[string]string{"param1": "https://localhost"}, "http://example#param1=https%3A%2F%2Flocalhost"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value#param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example#param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				// When.
				got := authorize.URLWithFragmentParams(testCase.url, testCase.params)

				// Then.
				if got != testCase.expected {
					t.Errorf("URLWithFragmentParams() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}

}
