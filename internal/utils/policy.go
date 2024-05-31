package utils

import (
	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type CheckPolicyAvailabilityFunc func(models.AuthnSession, *gin.Context) bool

type AuthnPolicy struct {
	Id              string
	AuthnSequence   []AuthnFunc
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

func NewPolicy(
	id string,
	isAvailableFunc CheckPolicyAvailabilityFunc,
	authnSequence ...AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		Id:              id,
		AuthnSequence:   authnSequence,
		IsAvailableFunc: isAvailableFunc,
	}
}

func GetAvailablePolicy(
	ctx Context,
	session models.AuthnSession,
) (
	policy AuthnPolicy,
	ok bool,
) {
	for _, policy = range ctx.Policies {
		if ok = policy.IsAvailableFunc(session, ctx.RequestContext); ok {
			return policy, true
		}
	}

	return AuthnPolicy{}, false
}
