package utils

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func setUp() (tearDown func()) {
	// Set up.

	// Tear down.
	return func() {
		// Restore global variables.
		stepMap = map[string]*AuthnStep{
			FinishFlowSuccessfullyStep.Id: FinishFlowSuccessfullyStep,
			FinishFlowWithFailureStep.Id:  FinishFlowWithFailureStep,
		}
		policyMap = make(map[string]AuthnPolicy)
	}
}

func TestNewStepShouldRegisterStep(t *testing.T) {
	tearDown := setUp()
	defer tearDown()
	// When
	stepId := "step_id"

	// Then
	NewStep(stepId, nil, nil, nil)

	// Assert
	if _, stepWasRegistered := stepMap[stepId]; !stepWasRegistered {
		t.Error("NewStep is not registering the step")
	}
}

func TestNewStepShouldReplaceNilNextSteps(t *testing.T) {
	tearDown := setUp()
	defer tearDown()
	// When
	stepId := "step_id"

	// Then
	step := NewStep(stepId, nil, nil, nil)

	// Assert
	if step.NextStepIfFailure != FinishFlowWithFailureStep {
		t.Error("failure step was not replaced")
	}
	if step.NextStepIfSuccess != FinishFlowSuccessfullyStep {
		t.Error("failure step was not replaced")
	}
}

func TestGetStep(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

	// When
	step := &AuthnStep{
		Id:                "step_id",
		NextStepIfSuccess: nil,
		NextStepIfFailure: nil,
		AuthnFunc:         nil,
	}
	stepMap[step.Id] = step

	// Then
	selectedStep := GetStep(step.Id)

	// Assert
	if selectedStep != step {
		t.Error("GetStep is not fetching the right step")
	}
}

func TestAddPolicyRegistersStep(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

	// When
	availablePolicy := AuthnPolicy{
		Id:              "policy_id",
		FirstStep:       nil,
		IsAvailableFunc: nil,
	}

	// Then
	AddPolicy(availablePolicy)

	// Assert
	if _, policyWasRegistered := policyMap[availablePolicy.Id]; !policyWasRegistered {
		t.Error("NewPolicy is not registering the policy")
	}
}

func TestGetPolicy(t *testing.T) {
	tearDown := setUp()
	defer tearDown()

	// When
	unavailablePolicy := AuthnPolicy{
		Id:        "unavailable_policy",
		FirstStep: nil,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool {
			return false
		},
	}
	policyMap[unavailablePolicy.Id] = unavailablePolicy

	availablePolicy := AuthnPolicy{
		Id:        "available_policy",
		FirstStep: nil,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool {
			return true
		},
	}
	policyMap[availablePolicy.Id] = availablePolicy

	// Then
	policy, policyIsAvailable := GetPolicy(models.Client{}, nil)

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
	unavailablePolicy := AuthnPolicy{
		Id:        "unavailable_policy",
		FirstStep: nil,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool {
			return false
		},
	}
	policyMap[unavailablePolicy.Id] = unavailablePolicy

	// Then
	_, policyIsAvailable := GetPolicy(models.Client{}, nil)

	// Assert
	if policyIsAvailable {
		t.Error("GetPolicy should not find any policy")
	}

}

func TestFinishFlowSuccessfullyStepShouldHaveNoNextSteps(t *testing.T) {
	if FinishFlowSuccessfullyStep.NextStepIfSuccess != nil || FinishFlowSuccessfullyStep.NextStepIfFailure != nil {
		t.Errorf("the step: %s should not have next steps", FinishFlowSuccessfullyStep.Id)
	}
}

func TestFinishFlowSuccessfullyStep(t *testing.T) {
	// When
	session := &models.AuthnSession{
		RedirectUri:   "https://example.com",
		State:         "random_state",
		ResponseTypes: []constants.ResponseType{constants.Code},
	}
	ctx := GetMockedContext()

	// Then
	FinishFlowSuccessfullyStep.AuthnFunc(ctx, session)

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

func TestFinishFlowWithFailureStepShouldHaveNoNextSteps(t *testing.T) {
	if FinishFlowWithFailureStep.NextStepIfSuccess != nil || FinishFlowWithFailureStep.NextStepIfFailure != nil {
		t.Errorf("the step: %s should not have next steps", FinishFlowWithFailureStep.Id)
	}
}

func TestFinishFlowWithFailureStep(t *testing.T) {
	// When
	session := &models.AuthnSession{
		RedirectUri: "https://example.com",
		State:       "random_state",
	}
	ctx := GetMockedContext()

	// Then
	FinishFlowWithFailureStep.AuthnFunc(ctx, session)

	// Assert
	if http.StatusFound != ctx.RequestContext.Writer.Status() {
		t.Errorf("response status is: %v, but should be 302", ctx.RequestContext.Request.Response.StatusCode)
	}
	expectedRedirectUrl := fmt.Sprintf(session.RedirectUri+"?error=%s&error_description=%s&state=%s", "access_denied", "access+denied", session.State)
	if redirectUrl := ctx.RequestContext.Writer.Header().Get("Location"); redirectUrl != expectedRedirectUrl {
		t.Errorf("the redirect url: %s is not as expected", redirectUrl)
	}
}
