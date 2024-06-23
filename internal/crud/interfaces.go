package crud

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
)

type ClientManager interface {
	Create(ctx context.Context, client models.Client) error
	Update(ctx context.Context, id string, client models.Client) error
	Get(ctx context.Context, id string) (models.Client, error)
	Delete(ctx context.Context, id string) error
}

type GrantSessionManager interface {
	CreateOrUpdate(ctx context.Context, grantSession models.GrantSession) error
	Get(ctx context.Context, id string) (models.GrantSession, error)
	GetByTokenId(ctx context.Context, tokenId string) (models.GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (models.GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionManager interface {
	CreateOrUpdate(ctx context.Context, session models.AuthnSession) error
	GetByCallbackId(ctx context.Context, callbackId string) (models.AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (models.AuthnSession, error)
	GetByRequestUri(ctx context.Context, requestUri string) (models.AuthnSession, error)
	Delete(ctx context.Context, id string) error
}
