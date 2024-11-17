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
