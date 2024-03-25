package crud

import "github.com/luikymagno/auth-server/internal/models"

type ScopeManager interface {
	Create(scope models.Scope) error
	Update(id string, scope models.Scope) error
	Get(id string) (models.Scope, error)
	Delete(id string) error
}

type TokenModelManager interface {
	Create(model models.TokenModel) error
	Update(id string, model models.TokenModel) error
	Get(id string) (models.TokenModel, error)
	Delete(id string) error
}

type ClientManager interface {
	Create(client models.Client) error
	Update(id string, client models.Client) error
	Get(id string) (models.Client, error)
	Delete(id string) error
}

type TokenSessionManager interface {
	Create(token models.Token) error
	Get(id string) (models.Token, error)
	Delete(id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(session models.AuthnSession) error
	GetByCallbackId(callbackId string) (models.AuthnSession, error)
	GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error)
	GetByRequestUri(requestUri string) (models.AuthnSession, error)
	Delete(id string) error
}
