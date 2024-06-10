package utils

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type CheckPolicyAvailabilityFunc func(Context, models.Client, models.AuthnSession) bool

type AuthnPolicy struct {
	Id              string
	AuthnFunc       AuthnFunc
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

func NewPolicy(
	id string,
	isAvailableFunc CheckPolicyAvailabilityFunc,
	authnFunc AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		Id:              id,
		AuthnFunc:       authnFunc,
		IsAvailableFunc: isAvailableFunc,
	}
}
