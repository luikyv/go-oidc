package utils_test

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestGetPolicy(t *testing.T) {

	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		func(c models.AuthnSession, ctx *gin.Context) bool {
			return false
		},
	)
	availablePolicy := utils.NewPolicy(
		"available_policy",
		func(c models.AuthnSession, ctx *gin.Context) bool {
			return true
		},
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []utils.AuthnPolicy{unavailablePolicy, availablePolicy}

	// Then
	policy, policyIsAvailable := ctx.GetAvailablePolicy(models.AuthnSession{})

	// Assert
	if !policyIsAvailable {
		t.Error("GetPolicy is not fetching any policy")
	}
	if policy.Id != availablePolicy.Id {
		t.Error("GetPolicy is not fetching the right policy")
	}

}

func TestGetPolicyNoPolicyAvailable(t *testing.T) {
	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		func(c models.AuthnSession, ctx *gin.Context) bool {
			return false
		},
	)
	ctx := utils.GetDummyTestContext()
	ctx.Policies = []utils.AuthnPolicy{unavailablePolicy}

	// Then
	_, policyIsAvailable := ctx.GetAvailablePolicy(models.AuthnSession{})

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}
