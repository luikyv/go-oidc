package utils_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPolicy_HappyPath(t *testing.T) {

	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := goidc.NewPolicy(
		"available_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := utils.GetTestContext()
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy, availablePolicy}

	// When.
	policy, policyIsAvailable := ctx.GetAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.True(t, policyIsAvailable, "GetPolicy is not fetching any policy")
	assert.Equal(t, policy.ID, availablePolicy.ID, "GetPolicy is not fetching the right policy")
}

func TestGetPolicy_NoPolicyAvailable(t *testing.T) {
	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := utils.GetTestContext()
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy}

	// When.
	_, policyIsAvailable := ctx.GetAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.False(t, policyIsAvailable, "GetPolicy is not fetching any policy")
}
