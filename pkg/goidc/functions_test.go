package goidc_test

import (
	"fmt"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestSplitStringWithSpaces_HappyPath(t *testing.T) {

	// Given.
	var cases = []struct {
		s        string
		expected []string
	}{
		{"scope1 scope2", []string{"scope1", "scope2"}},
		{"scope1", []string{"scope1"}},
		{"    ", []string{}},
	}

	for i, c := range cases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				assert.Equal(t, c.expected, goidc.SplitStringWithSpaces(c.s), "result is not as expected")
			},
		)
	}
}

func TestGenerateRandomString_ShouldGenerateRandomStrings(t *testing.T) {
	assert.NotEqual(t, goidc.RandomString(10, 10), goidc.RandomString(10, 10))
}

func TestGenerateRandomString_WithDifferentLengths(t *testing.T) {

	// Given.
	var lengthRanges = []struct {
		minLength int
		maxLength int
	}{
		{10, 15},
		{20, 30},
		{10, 10},
	}

	for i, lengthRange := range lengthRanges {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// When.
				randString := goidc.RandomString(lengthRange.minLength, lengthRange.maxLength)

				// Then.
				assert.GreaterOrEqual(t, len(randString), lengthRange.minLength, "invalid length")
				assert.LessOrEqual(t, len(randString), lengthRange.maxLength, "invalid length")
			},
		)
	}
}

func TestGenerateCallbackID(t *testing.T) {
	assert.Len(t, goidc.CallbackID(), goidc.CallbackIDLength, "invalid length")
}

func TestGenerateAuthorizationCode(t *testing.T) {
	assert.Len(t, goidc.AuthorizationCode(), goidc.AuthorizationCodeLength, "invalid length")
}

func TestContainsAll(t *testing.T) {
	assert.True(t, goidc.ContainsAll([]string{"a", "b", "c"}, "a", "b"), "super set should contain sub set")
	assert.False(t, goidc.ContainsAll([]int{1}, 1, 2), "super set should not contain sub set")
	assert.True(t, goidc.ContainsAll([]int{1, 2}, 1, 2), "super set should contain sub set")
}

func TestContainsAllScopes(t *testing.T) {

	// Given.
	testCases := []struct {
		scopeSuperSet    string
		scopeSubSet      string
		shouldContainAll bool
	}{
		{"scope1 scope2 scope3", "scope1", true},
		{"scope1 scope2 scope3", "scope2", true},
		{"scope1 scope2 scope3", "scope3", true},
		{"scope1", "scope1", true},
		{"scope1 scope2 scope3", "scope1 scope3", true},
		{"scope1 scope2 scope3", "scope1 scope2 scope3", true},
		{"scope1 scope2 scope3", "scope1 ", false},
		{"scope1 scope2 scope3", "scope4", false},
		{"scope1 scope2 scope3", "scope1 scope34 scope2", false},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i+1), func(t *testing.T) {
			assert.Equal(t, testCase.shouldContainAll, goidc.ContainsAllScopes(testCase.scopeSuperSet, testCase.scopeSubSet))
		})
	}
}
