package utils_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestGetPolicy_HappyPath(t *testing.T) {

	// When
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := goidc.NewPolicy(
		"available_policy",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy, availablePolicy}

	// Then
	policy, policyIsAvailable := ctx.GetAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Assert
	if !policyIsAvailable {
		t.Error("GetPolicy is not fetching any policy")
	}
	if policy.ID != availablePolicy.ID {
		t.Error("GetPolicy is not fetching the right policy")
	}

}

func TestGetPolicy_NoPolicyAvailable(t *testing.T) {
	// When
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy}

	// Then
	_, policyIsAvailable := ctx.GetAvailablePolicy(goidc.Client{}, &goidc.AuthnSession{})

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}
