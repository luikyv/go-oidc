package utils

import (
	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func init() {
	stepMap = make(map[string]AuthnStep)
	policyMap = make(map[string]AuthnPolicy)
}

var stepMap map[string]AuthnStep
var policyMap map[string]AuthnPolicy

//---------------------------------------- Step ----------------------------------------//

type AuthnFunc func(Context, *models.AuthnSession) (constants.AuthnStatus, error)

type AuthnStep struct {
	Id        string
	AuthnFunc AuthnFunc
}

func GetStep(id string) AuthnStep {
	return stepMap[id]
}

// Create a new step and register it internally.
func NewStep(id string, authnFunc AuthnFunc) AuthnStep {
	step := AuthnStep{
		Id:        id,
		AuthnFunc: authnFunc,
	}
	stepMap[step.Id] = step

	return step
}

//---------------------------------------- Policy ----------------------------------------//

type CheckPolicyAvailabilityFunc func(models.AuthnSession, *gin.Context) bool

type AuthnPolicy struct {
	Id              string
	StepIdSequence  []string
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

func NewPolicy(
	id string,
	isAvailableFunc CheckPolicyAvailabilityFunc,
	stepSequence ...AuthnStep,
) AuthnPolicy {
	stepIdSequence := make([]string, len(stepSequence))
	for i, step := range stepSequence {
		stepIdSequence[i] = step.Id
	}

	policy := AuthnPolicy{
		Id:              id,
		StepIdSequence:  stepIdSequence,
		IsAvailableFunc: isAvailableFunc,
	}
	policyMap[policy.Id] = policy

	return policy
}
