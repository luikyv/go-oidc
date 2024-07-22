package goidc_test

import (
	"fmt"
	"testing"

	"github.com/luikyv/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// When
	s1, err1 := goidc.RandomString(10)
	s2, err2 := goidc.RandomString(10)

	// Then.
	require.Nil(t, err1)
	require.Nil(t, err2)
	assert.NotEqual(t, s1, s2)
}

func TestGenerateRandomString_WithDifferentLengths(t *testing.T) {

	// Given.
	var lengthRanges = []struct {
		length int
	}{
		{10},
		{20},
		{10},
	}

	for i, lengthRange := range lengthRanges {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// When.
				randString, err := goidc.RandomString(lengthRange.length)

				// Then.
				assert.Nil(t, err)
				assert.Len(t, randString, lengthRange.length, "invalid length")
			},
		)
	}
}

func TestGenerateCallbackID(t *testing.T) {
	// When.
	callbackID, err := goidc.CallbackID()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, callbackID, goidc.CallbackIDLength, "invalid length")
}

func TestGenerateAuthorizationCode(t *testing.T) {
	// When.
	code, err := goidc.AuthorizationCode()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, code, goidc.AuthorizationCodeLength, "invalid length")
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
