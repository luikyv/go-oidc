package strutil_test

import (
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/strutil"
)

func TestContainsOpenID(t *testing.T) {
	tests := []struct {
		name   string
		scopes string
		want   bool
	}{
		{name: "contains openid", scopes: "openid profile email", want: true},
		{name: "missing openid", scopes: "profile email", want: false},
		{name: "openid as substring does not count", scopes: "myopenid profile", want: false},
		{name: "extra whitespace is ignored", scopes: "  openid   profile  ", want: true},
		{name: "empty", scopes: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.ContainsOpenID(test.scopes)
			if got != test.want {
				t.Fatalf("ContainsOpenID(%q) = %v, want %v", test.scopes, got, test.want)
			}
		})
	}
}

func TestContainsOfflineAccess(t *testing.T) {
	tests := []struct {
		name   string
		scopes string
		want   bool
	}{
		{name: "contains offline_access", scopes: "openid offline_access", want: true},
		{name: "missing offline_access", scopes: "openid profile", want: false},
		{name: "offline access as substring does not count", scopes: "offline_access_token", want: false},
		{name: "extra whitespace is ignored", scopes: "  offline_access   profile  ", want: true},
		{name: "empty", scopes: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.ContainsOfflineAccess(test.scopes)
			if got != test.want {
				t.Fatalf("ContainsOfflineAccess(%q) = %v, want %v", test.scopes, got, test.want)
			}
		})
	}
}

func TestRandom(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{name: "zero length", length: 0},
		{name: "non zero length", length: 32},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.Random(test.length)
			if len(got) != test.length {
				t.Fatalf("len(Random(%d)) = %d, want %d", test.length, len(got), test.length)
			}
			if strings.ContainsAny(got, "!@#$%^&*()-_=+[]{}<>?/\\|`~ \t\n") {
				t.Fatalf("Random(%d) generated unexpected characters: %q", test.length, got)
			}
		})
	}

	t.Run("different values across calls", func(t *testing.T) {
		first := strutil.Random(32)
		second := strutil.Random(32)
		if first == second {
			t.Fatalf("Random(32) produced the same value twice: %q", first)
		}
	})
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{name: "keeps normalized http url", url: "http://example.com", want: "http://example.com"},
		{name: "keeps path", url: "http://example.com/test", want: "http://example.com/test"},
		{name: "removes trailing slash from path", url: "http://example.com/test/", want: "http://example.com/test"},
		{name: "removes root trailing slash", url: "http://example.com/", want: "http://example.com"},
		{name: "trims dangling colon", url: "http://example.com:/", want: "http://example.com"},
		{name: "removes default http port", url: "http://example.com:80/", want: "http://example.com"},
		{name: "removes default https port", url: "https://example.com:443", want: "https://example.com"},
		{name: "keeps non default port", url: "https://example.com:8443", want: "https://example.com:8443"},
		{name: "lowercases scheme and host", url: "HTTPS://EXAMPLE.COM/Path", want: "https://example.com/Path"},
		{name: "removes query and fragment", url: "https://example.com/callback?code=123#frag", want: "https://example.com/callback"},
		{name: "invalid url", url: "://bad url", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := strutil.NormalizeURL(test.url)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", test.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("NormalizeURL(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "https url", value: "https://example.com", want: true},
		{name: "url with path", value: "https://example.com/callback", want: true},
		{name: "missing scheme", value: "example.com/callback", want: false},
		{name: "missing host", value: "https:///callback", want: false},
		{name: "plain text", value: "client-id", want: false},
		{name: "invalid url", value: "https://exa mple.com", want: false},
		{name: "urn is not url", value: "urn:example:client", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.IsURL(test.value)
			if got != test.want {
				t.Fatalf("IsURL(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestURLWithQueryParams(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		params map[string]string
		want   string
	}{
		{name: "no params", url: "http://example", params: map[string]string{}, want: "http://example"},
		{name: "single param", url: "http://example", params: map[string]string{"param1": "value1"}, want: "http://example?param1=value1"},
		{name: "keeps existing query", url: "http://example?param=value", params: map[string]string{"param1": "value1"}, want: "http://example?param=value&param1=value1"},
		{name: "multiple params", url: "http://example", params: map[string]string{"param1": "value1", "param2": "value2"}, want: "http://example?param1=value1&param2=value2"},
		{name: "overwrites existing param", url: "http://example?param=value", params: map[string]string{"param": "other"}, want: "http://example?param=other"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.URLWithQueryParams(test.url, test.params)
			if got != test.want {
				t.Fatalf("URLWithQueryParams(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}

func TestURLWithFragmentParams(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		params map[string]string
		want   string
	}{
		{name: "no params", url: "http://example", params: map[string]string{}, want: "http://example"},
		{name: "single param", url: "http://example", params: map[string]string{"param1": "value1"}, want: "http://example#param1=value1"},
		{name: "escapes values", url: "http://example", params: map[string]string{"param1": "https://localhost"}, want: "http://example#param1=https%3A%2F%2Flocalhost"},
		{name: "keeps query", url: "http://example?param=value", params: map[string]string{"param1": "value1"}, want: "http://example?param=value#param1=value1"},
		{name: "multiple params", url: "http://example", params: map[string]string{"param1": "value1", "param2": "value2"}, want: "http://example#param1=value1&param2=value2"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strutil.URLWithFragmentParams(test.url, test.params)
			if got != test.want {
				t.Fatalf("URLWithFragmentParams(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}
