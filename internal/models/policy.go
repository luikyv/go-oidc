package models

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

//---------------------------------------- Step ----------------------------------------//

type AuthnFunc func(*AuthnSession, *gin.Context) constants.AuthnStatus

type AuthnStep struct {
	Id                string
	NextStepIfSuccess *AuthnStep
	NextStepIfFailure *AuthnStep
	AuthnFunc         AuthnFunc
}

var stepMap map[string]*AuthnStep = make(map[string]*AuthnStep)

// Create a new step and register it internally.
func NewStep(id string, nextStepIfSuccess *AuthnStep, nextStepIfFailure *AuthnStep, authnFunc AuthnFunc) *AuthnStep {
	step := &AuthnStep{
		Id:                id,
		AuthnFunc:         authnFunc,
		NextStepIfSuccess: nextStepIfSuccess,
		NextStepIfFailure: nextStepIfFailure,
	}

	stepMap[step.Id] = step

	return step
}

func GetStep(id string) *AuthnStep {
	return stepMap[id]
}

var FinishFlowSuccessfullyStep *AuthnStep = NewStep(
	"finish_flow_successfully",
	nil,
	nil,
	func(session *AuthnSession, ctx *gin.Context) constants.AuthnStatus {
		authzCode := unit.GenerateAuthorizationCode()
		session.AuthorizationCode = authzCode

		params := make(map[string]string, 2)
		params["code"] = authzCode
		if session.State != "" {
			params["state"] = session.State
		}

		ctx.Redirect(http.StatusFound, unit.GetUrlWithParams(session.RedirectUri, params))
		return constants.Success
	},
)

var FinishFlowWithFailureStep *AuthnStep = NewStep(
	"finish_flow_with_failure",
	nil,
	nil,
	func(session *AuthnSession, ctx *gin.Context) constants.AuthnStatus {

		redirectError := issues.RedirectError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "access denied",
			RedirectUri:      session.RedirectUri,
			State:            session.State,
		}
		redirectError.BindErrorToResponse(ctx)

		return constants.Failure
	},
)

//---------------------------------------- Policy ----------------------------------------//

type CheckPolicyAvailabilityFunc func(Client, *gin.Context) bool

type AuthnPolicy struct {
	Id              string
	FirstStep       *AuthnStep
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

var policyMap map[string]AuthnPolicy = make(map[string]AuthnPolicy)

// Add a new policy by registering it internally.
func AddPolicy(policy AuthnPolicy) {
	policyMap[policy.Id] = policy
}

func GetPolicy(client Client, requestContext *gin.Context) (policy AuthnPolicy, policyIsAvailable bool) {
	for _, policy = range policyMap {
		if policyIsAvailable = policy.IsAvailableFunc(client, requestContext); policyIsAvailable {
			break
		}
	}
	return policy, policyIsAvailable
}
