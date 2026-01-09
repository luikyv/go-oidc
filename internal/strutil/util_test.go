package strutil_test

import (
	"fmt"
	"net/url"
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

func TestIsLoopbackURL(t *testing.T) {
	testCases := []struct {
		rawURL string
		want   bool
	}{
		// IPv4 loopback.
		{"http://127.0.0.1/callback", true},
		{"http://127.0.0.1:8080/callback", true},
		{"http://127.255.255.255/callback", true},
		// IPv6 loopback.
		{"http://[::1]/callback", true},
		{"http://[::1]:9000/callback", true},
		// Non-loopback IPv6 that starts with ::1 prefix (regression test).
		{"http://[::1:5]/callback", false},
		{"http://[::1:0:0:0:0:0:0]/callback", false},
		// Non-loopback addresses.
		{"http://localhost/callback", false}, // RFC 8252 7.3 specifies that the IP literal is used, not localhost
		{"http://example.com/callback", false},
		{"https://127.0.0.1/callback", false}, // https, not http
	}

	for _, tc := range testCases {
		t.Run(tc.rawURL, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			got := strutil.IsLoopbackURL(u)
			if got != tc.want {
				t.Errorf("IsLoopbackURL(%q) = %v, want %v", tc.rawURL, got, tc.want)
			}
		})
	}
}
