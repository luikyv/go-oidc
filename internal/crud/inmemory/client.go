package inmemory

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
)

type InMemoryClientManager struct {
	Clients map[string]goidc.Client
}

func NewInMemoryClientManager() *InMemoryClientManager {
	return &InMemoryClientManager{
		Clients: make(map[string]goidc.Client),
	}
}

func (manager *InMemoryClientManager) Create(_ context.Context, client goidc.Client) error {
	_, exists := manager.Clients[client.ID]
	if exists {
		return goidc.ErrorEntityAlreadyExists
	}

	manager.Clients[client.ID] = client
	return nil
}

func (manager *InMemoryClientManager) Update(_ context.Context, id string, client goidc.Client) error {
	_, exists := manager.Clients[id]
	if !exists {
		return goidc.ErrorEntityNotFound
	}

	manager.Clients[id] = client
	return nil
}

func (manager *InMemoryClientManager) Get(_ context.Context, id string) (goidc.Client, error) {
	client, exists := manager.Clients[id]
	if !exists {
		return goidc.Client{}, goidc.ErrorEntityNotFound
	}

	return client, nil
}

func (manager *InMemoryClientManager) Delete(_ context.Context, id string) error {
	delete(manager.Clients, id)
	return nil
}
