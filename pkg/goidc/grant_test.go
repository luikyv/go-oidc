package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGrantIsExpired(t *testing.T) {
	now := timeutil.TimestampNow()

	testCases := []struct {
		name      string
		expiresAt int
		want      bool
	}{
		{"expired", now - 10, true},
		{"exactly now", now, true},
		{"not expired", now + 10, false},
		{"zero means never expires", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			grant := goidc.Grant{ExpiresAtTimestamp: tc.expiresAt}

			// When.
			got := grant.IsExpired()

			// Then.
			if got != tc.want {
				t.Errorf("IsExpired() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestTokenIsExpired(t *testing.T) {
	now := timeutil.TimestampNow()

	testCases := []struct {
		name      string
		expiresAt int
		want      bool
	}{
		{"expired", now - 1, true},
		{"exactly now", now, true},
		{"not expired", now + 10, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			token := goidc.Token{ExpiresAtTimestamp: tc.expiresAt}

			// When.
			got := token.IsExpired()

			// Then.
			if got != tc.want {
				t.Errorf("IsExpired() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestTokenLifetimeSecs(t *testing.T) {
	// Given.
	token := goidc.Token{
		CreatedAtTimestamp: 1000,
		ExpiresAtTimestamp: 4600,
	}

	// When.
	got := token.LifetimeSecs()

	// Then.
	if got != 3600 {
		t.Errorf("LifetimeSecs() = %d, want 3600", got)
	}
}
