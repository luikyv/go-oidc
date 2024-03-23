package crud

import "github.com/luikymagno/auth-server/internal/models"

type ScopeGetResult struct {
	Scope models.Scope
	Error error
}

type ScopeManager interface {
	Create(scope models.Scope, ch chan error)
	Update(id string, scope models.Scope, ch chan error)
	Get(id string, ch chan ScopeGetResult)
	Delete(id string)
}

type TokenModelGetResult struct {
	TokenModel models.TokenModel
	Error      error
}

type TokenModelManager interface {
	Create(model models.TokenModel, ch chan error)
	Update(id string, model models.TokenModel, ch chan error)
	Get(id string, ch chan TokenModelGetResult)
	Delete(id string)
}

type ClientGetResult struct {
	Client models.Client
	Error  error
}

type ClientManager interface {
	Create(client models.Client, ch chan error)
	Update(id string, client models.Client, ch chan error)
	Get(id string, ch chan ClientGetResult)
	Delete(id string)
}

type TokenSessionGetResult struct {
	Token models.Token
	Error error
}

type TokenSessionManager interface {
	Create(token models.Token, ch chan error)
	Get(id string, ch chan TokenSessionGetResult)
	Delete(id string)
}

type AuthnSessionGetResult struct {
	Session models.AuthnSession
	Error   error
}

type AuthnSessionManager interface {
	CreateOrUpdate(session models.AuthnSession, ch chan error)
	GetByCallbackId(callbackId string, ch chan AuthnSessionGetResult)
	GetByAuthorizationCode(authorizationCode string, ch chan AuthnSessionGetResult)
	GetByRequestUri(requestUri string, ch chan AuthnSessionGetResult)
	Delete(id string)
}
