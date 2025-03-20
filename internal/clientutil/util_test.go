package clientutil_test

import (
	"fmt"
	"testing"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestAreScopesAllowed(t *testing.T) {
	// Given.
	scopes := []goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
		goidc.NewScope("scope3"),
	}

	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			ScopeIDs: "scope1 scope2 scope3",
		},
	}

	testCases := []struct {
		requestedScopes string
		want            bool
	}{
		{"scope1 scope3", true},
		{"scope3 scope2", true},
		{"invalid_scope scope3", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				got := clientutil.AreScopesAllowed(
					client,
					scopes,
					testCase.requestedScopes,
				)
				if got != testCase.want {
					t.Errorf("AreScopesAllowed() = %t, want %t", got, testCase.want)
				}
			},
		)
	}
}
