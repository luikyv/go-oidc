package utils

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type CheckPolicyAvailabilityFunc func(Context, models.AuthnSession) bool

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
