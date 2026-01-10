package strutil_test

import (
	"fmt"
	"testing"

	"github.com/luikyv/go-oidc/internal/strutil"
)

func TestNormalizeURL(t *testing.T) {
	// Given.
	testCases := []struct {
		url  string
		want string
	}{
		{
			url:  "http://example.com",
			want: "http://example.com",
		},
		{
			url:  "http://example.com/test",
			want: "http://example.com/test",
		},
		{
			url:  "http://example.com/test/",
			want: "http://example.com/test",
		},
		{
			url:  "http://example.com/",
			want: "http://example.com",
		},
		{
			url:  "http://example.com:/",
			want: "http://example.com",
		},
		{
			url:  "http://example.com:80/",
			want: "http://example.com",
		},
		{
			url:  "https://example.com:443",
			want: "https://example.com",
		},
		{
			url:  "https://example.com:8443",
			want: "https://example.com:8443",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			// When.
			normalizedURL, err := strutil.NormalizeURL(testCase.url)

			// Then.
			if err != nil {
				t.Fatal(err)
			}

			if normalizedURL != testCase.want {
				t.Errorf("got %s, want %s", normalizedURL, testCase.want)
			}
		})
	}

}

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
				got := strutil.URLWithQueryParams(testCase.url, testCase.params)

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
				got := strutil.URLWithFragmentParams(testCase.url, testCase.params)

				// Then.
				if got != testCase.expected {
					t.Errorf("URLWithFragmentParams() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}

}
