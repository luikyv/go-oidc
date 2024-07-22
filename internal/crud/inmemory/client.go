package inmemory

import (
	"context"

	"github.com/luikyv/goidc/pkg/goidc"
)

type ClientManager struct {
	Clients map[string]*goidc.Client
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		Clients: make(map[string]*goidc.Client),
	}
}

func (manager *ClientManager) CreateOrUpdate(
	_ context.Context,
	client *goidc.Client,
) error {
	manager.Clients[client.ID] = client
	return nil
}

func (manager *ClientManager) Get(
	_ context.Context,
	id string,
) (
	*goidc.Client,
	error,
) {
	client, exists := manager.Clients[id]
	if !exists {
		return nil, goidc.ErrorEntityNotFound
	}

	return client, nil
}

func (manager *ClientManager) Delete(
	_ context.Context,
	id string,
) error {
	delete(manager.Clients, id)
	return nil
}
