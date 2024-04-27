package utils_test

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

func setUp() (tearDown func()) {
	// Set up.

	// Tear down.
	return func() {
		for k := range utils.StepMap {
			delete(utils.StepMap, k)
		}
	}
}

func TestNewStepShouldRegisterStep(t *testing.T) {
	tearDown := setUp()
	defer tearDown()
	// When
	stepId := "step_id"

	// Then
	utils.NewStep(stepId, nil)

	// Assert
	if _, stepWasRegistered := utils.StepMap[stepId]; !stepWasRegistered {
		t.Error("NewStep is not registering the step")
	}
}

func TestGetStep(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

	// When
	step := utils.AuthnStep{
		Id:        "step_id",
		AuthnFunc: nil,
	}
	utils.StepMap[step.Id] = step

	// Then
	selectedStep := utils.GetStep(step.Id)

	// Assert
	if selectedStep.Id != step.Id {
		t.Error("GetStep is not fetching the right step")
	}
}

func TestGetPolicy(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

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
	ctx := utils.GetMockedContext()
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
	tearDown := setUp()
	defer tearDown()

	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		func(c models.AuthnSession, ctx *gin.Context) bool {
			return false
		},
	)
	ctx := utils.GetMockedContext()
	ctx.Policies = []utils.AuthnPolicy{unavailablePolicy}

	// Then
	_, policyIsAvailable := ctx.GetAvailablePolicy(models.AuthnSession{})

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}
