package utils_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func setUp() (tearDown func()) {
	// Set up.
	utils.StepMap[utils.FinishFlowSuccessfullyStep.Id] = utils.FinishFlowSuccessfullyStep
	utils.StepMap[utils.FinishFlowWithFailureStep.Id] = utils.FinishFlowWithFailureStep

	// Tear down.
	return func() {
		for k := range utils.StepMap {
			delete(utils.StepMap, k)
		}
		for k := range utils.PolicyMap {
			delete(utils.PolicyMap, k)
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

func TestNewPolicyRegistersStep(t *testing.T) {
	// When
	tearDown := setUp()
	defer tearDown()

	// Then
	availablePolicy := utils.NewPolicy(
		"policy_id",
		[]utils.AuthnStep{},
		nil,
	)

	// Assert
	if _, policyWasRegistered := utils.PolicyMap[availablePolicy.Id]; !policyWasRegistered {
		t.Error("NewPolicy is not registering the policy")
	}
}

func TestGetPolicy(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

	// When
	unavailablePolicy := utils.NewPolicy(
		"unavailable_policy",
		[]utils.AuthnStep{},
		func(c models.Client, ctx *gin.Context) bool {
			return false
		},
	)
	availablePolicy := utils.NewPolicy(
		"available_policy",
		[]utils.AuthnStep{},
		func(c models.Client, ctx *gin.Context) bool {
			return true
		},
	)
	ctx := utils.GetMockedContext()
	ctx.PolicyIds = []string{unavailablePolicy.Id, availablePolicy.Id}

	// Then
	policy, policyIsAvailable := utils.GetPolicy(ctx, models.Client{})

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
		[]utils.AuthnStep{},
		func(c models.Client, ctx *gin.Context) bool {
			return false
		},
	)
	ctx := utils.GetMockedContext()
	ctx.PolicyIds = []string{unavailablePolicy.Id}

	// Then

	_, policyIsAvailable := utils.GetPolicy(ctx, models.Client{})

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}

func TestFinishFlowSuccessfullyStep(t *testing.T) {
	// When
	session := &models.AuthnSession{
		RedirectUri:  "https://example.com",
		State:        "random_state",
		ResponseType: constants.Code,
	}
	ctx := utils.GetMockedContext()

	// Then
	utils.FinishFlowSuccessfullyStep.AuthnFunc(ctx, session)

	// Assert
	if session.AuthorizationCode == "" {
		t.Error("the authorization code was not filled")
	}
	if http.StatusFound != ctx.RequestContext.Writer.Status() {
		t.Errorf("response status is: %v, but should be 302", ctx.RequestContext.Request.Response.StatusCode)
	}
	expectedRedirectUrl := fmt.Sprintf(session.RedirectUri+"?code=%s&state=%s", session.AuthorizationCode, session.State)
	if redirectUrl := ctx.RequestContext.Writer.Header().Get("Location"); redirectUrl != expectedRedirectUrl {
		t.Errorf("the redirect url: %s is not as expected", redirectUrl)
	}
}

func TestFinishFlowWithFailureStep(t *testing.T) {
	// When
	session := &models.AuthnSession{
		RedirectUri: "https://example.com",
		State:       "random_state",
	}
	ctx := utils.GetMockedContext()

	// Then
	utils.FinishFlowWithFailureStep.AuthnFunc(ctx, session)

	// Assert
	if http.StatusFound != ctx.RequestContext.Writer.Status() {
		t.Errorf("response status is: %v, but should be 302", ctx.RequestContext.Request.Response.StatusCode)
	}
	expectedRedirectUrl := fmt.Sprintf(session.RedirectUri+"?error=%s&error_description=%s&state=%s", "access_denied", "access+denied", session.State)
	if redirectUrl := ctx.RequestContext.Writer.Header().Get("Location"); redirectUrl != expectedRedirectUrl {
		t.Errorf("the redirect url: %s is not as expected", redirectUrl)
	}
}
