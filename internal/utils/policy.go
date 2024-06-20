package utils

import (
	"github.com/luikymagno/goidc/internal/constants"
	"github.com/luikymagno/goidc/internal/models"
)

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type SetUpPolicyFunc func(ctx Context, client models.Client, session *models.AuthnSession) (selected bool)

type AuthnPolicy struct {
	Id        string
	AuthnFunc AuthnFunc
	SetUpFunc SetUpPolicyFunc
}

// Create a policy that will be selected based on setUpFunc and that authenticates users with authnFunc.
func NewPolicy(
	id string,
	setUpFunc SetUpPolicyFunc,
	authnFunc AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		Id:        id,
		AuthnFunc: authnFunc,
		SetUpFunc: setUpFunc,
	}
}
