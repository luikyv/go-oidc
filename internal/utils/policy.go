package utils

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func init() {
	// Register the default steps
	stepMap[FinishFlowSuccessfullyStep.Id] = FinishFlowSuccessfullyStep
	stepMap[FinishFlowWithFailureStep.Id] = FinishFlowWithFailureStep
}

//---------------------------------------- Step ----------------------------------------//

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type AuthnStep struct {
	Id                string
	NextStepIfSuccess *AuthnStep
	NextStepIfFailure *AuthnStep
	AuthnFunc         AuthnFunc
}

var stepMap map[string]*AuthnStep = make(map[string]*AuthnStep)

func GetStep(id string) *AuthnStep {
	return stepMap[id]
}

var FinishFlowSuccessfullyStep *AuthnStep = &AuthnStep{
	Id:                "finish_flow_successfully",
	NextStepIfSuccess: nil,
	NextStepIfFailure: nil,
	AuthnFunc: func(ctx Context, session *models.AuthnSession) constants.AuthnStatus {

		params := make(map[string]string)

		// Generate the authorization code if the client requested it.
		if slices.Contains(session.ResponseTypes, constants.Code) {
			session.AuthorizationCode = unit.GenerateAuthorizationCode()
			session.AuthorizedAtTimestamp = unit.GetTimestampNow()
			params[string(constants.Code)] = session.AuthorizationCode
		}

		// Generate an ID token if the client requested it.
		if slices.Contains(session.ResponseTypes, constants.IdToken) {
			tokenModel, err := ctx.TokenModelManager.Get(session.TokenModelId)
			if err != nil {
				session.SetError(constants.InternalError, "error generating id token")
				return FinishFlowWithFailureStep.AuthnFunc(ctx, session)
			}
			params[string(constants.IdToken)] = tokenModel.GenerateIdToken(
				models.NewAuthorizationCodeGrantTokenContextInfoFromAuthnSession(*session),
			)
		}

		if session.State != "" {
			params["state"] = session.State
		}

		ctx.RequestContext.Redirect(http.StatusFound, unit.GetUrlWithParams(session.RedirectUri, params))
		return constants.Success
	},
}

var FinishFlowWithFailureStep *AuthnStep = &AuthnStep{
	Id:                "finish_flow_with_failure",
	NextStepIfSuccess: nil,
	NextStepIfFailure: nil,
	AuthnFunc: func(ctx Context, session *models.AuthnSession) constants.AuthnStatus {

		errorCode := constants.AccessDenied
		errorDescription := "access denied"
		if session.ErrorCode != "" {
			errorCode = session.ErrorCode
			errorDescription = session.ErrorDescription
		}
		redirectError := issues.RedirectError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
			RedirectUri:      session.RedirectUri,
			State:            session.State,
		}

		redirectError.BindErrorToResponse(ctx.RequestContext)

		return constants.Failure
	},
}

// Create a new step and register it internally.
func NewStep(id string, nextStepIfSuccess *AuthnStep, nextStepIfFailure *AuthnStep, authnFunc AuthnFunc) *AuthnStep {
	if nextStepIfFailure == nil {
		nextStepIfFailure = FinishFlowWithFailureStep
	}
	if nextStepIfSuccess == nil {
		nextStepIfSuccess = FinishFlowSuccessfullyStep
	}
	step := &AuthnStep{
		Id:                id,
		AuthnFunc:         authnFunc,
		NextStepIfSuccess: nextStepIfSuccess,
		NextStepIfFailure: nextStepIfFailure,
	}
	stepMap[step.Id] = step

	return step
}

//---------------------------------------- Policy ----------------------------------------//

type CheckPolicyAvailabilityFunc func(models.Client, *gin.Context) bool

type AuthnPolicy struct {
	Id              string
	FirstStep       *AuthnStep
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

var policyMap map[string]AuthnPolicy = make(map[string]AuthnPolicy)

func NewPolicy(
	id string,
	firstStep *AuthnStep,
	isAvailableFunc CheckPolicyAvailabilityFunc,
) AuthnPolicy {
	return AuthnPolicy{
		Id:              id,
		FirstStep:       firstStep,
		IsAvailableFunc: isAvailableFunc,
	}
}

// Add a new policy by registering it internally.
func AddPolicy(policy AuthnPolicy) {
	policyMap[policy.Id] = policy
}

func GetPolicy(client models.Client, requestContext *gin.Context) (policy AuthnPolicy, policyIsAvailable bool) {
	for _, policy = range policyMap {
		if policyIsAvailable = policy.IsAvailableFunc(client, requestContext); policyIsAvailable {
			break
		}
	}
	return policy, policyIsAvailable
}
