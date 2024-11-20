package hashutil_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/hashutil"
)

func TestThumbprint(t *testing.T) {
	// Given.
	testCases := []struct {
		input string
		want  string
	}{
		{
			input: "test",
			want:  "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
		},
		{
			input: "test2",
			want:  "YDA64iuZiGG847KPM-7BvnWKITyGyTwHbb6fVYwRx1I",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			// When.
			thumbprint := hashutil.Thumbprint(testCase.input)

			// Then.
			if thumbprint != testCase.want {
				t.Errorf("got %s, want %s", thumbprint, testCase.want)
			}
		})
	}
}

func TestHalfHash(t *testing.T) {
	// Given.
	testCases := []struct {
		input string
		alg   jose.SignatureAlgorithm
		want  string
	}{
		{
			input: "rs256",
			alg:   jose.RS256,
			want:  "mRCcNV8hQeoi1kP5GmbbJg",
		},
		{
			input: "rs384",
			alg:   jose.RS384,
			want:  "hgd3-_rJs8dp_6Ac-oZS9U5NSuZSCExp",
		},
		{
			input: "rs512",
			alg:   jose.RS512,
			want:  "DUcIk-W2a9h9Gs2qWY9Awn7XvdLoHSVKXxWj4XwyRbc",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			// When.
			thumbprint := hashutil.HalfHash(testCase.input, testCase.alg)

			// Then.
			if thumbprint != testCase.want {
				t.Errorf("got %s, want %s", thumbprint, testCase.want)
			}
		})
	}
}
