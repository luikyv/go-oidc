package utils_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestGetPolicy_HappyPath(t *testing.T) {

	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := utils.NewPolicy(
		"available_policy",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []utils.AuthnPolicy{unavailablePolicy, availablePolicy}

	// Then
	policy, policyIsAvailable := ctx.GetAvailablePolicy(models.Client{}, &models.AuthnSession{})

	// Assert
	if !policyIsAvailable {
		t.Error("GetPolicy is not fetching any policy")
	}
	if policy.Id != availablePolicy.Id {
		t.Error("GetPolicy is not fetching the right policy")
	}

}

func TestGetPolicy_NoPolicyAvailable(t *testing.T) {
	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []utils.AuthnPolicy{unavailablePolicy}

	// Then
	_, policyIsAvailable := ctx.GetAvailablePolicy(models.Client{}, &models.AuthnSession{})

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}
