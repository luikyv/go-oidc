package crud

import "github.com/luikymagno/goidc/internal/models"

type ClientManager interface {
	Create(client models.Client) error
	Update(id string, client models.Client) error
	Get(id string) (models.Client, error)
	Delete(id string) error
}

type GrantSessionManager interface {
	CreateOrUpdate(grantSession models.GrantSession) error
	Get(id string) (models.GrantSession, error)
	GetByTokenId(tokenId string) (models.GrantSession, error)
	GetByRefreshToken(refreshToken string) (models.GrantSession, error)
	Delete(id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(session models.AuthnSession) error
	GetByCallbackId(callbackId string) (models.AuthnSession, error)
	GetByAuthorizationCode(authorizationCode string) (models.AuthnSession, error)
	GetByRequestUri(requestUri string) (models.AuthnSession, error)
	Delete(id string) error
}
