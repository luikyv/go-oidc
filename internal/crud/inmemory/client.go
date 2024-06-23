package inmemory

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
)

type InMemoryClientManager struct {
	Clients map[string]models.Client
}

func NewInMemoryClientManager() *InMemoryClientManager {
	return &InMemoryClientManager{
		Clients: make(map[string]models.Client),
	}
}

func (manager *InMemoryClientManager) Create(_ context.Context, client models.Client) error {
	_, exists := manager.Clients[client.Id]
	if exists {
		return models.ErrorEntityAlreadyExists
	}

	manager.Clients[client.Id] = client
	return nil
}

func (manager *InMemoryClientManager) Update(_ context.Context, id string, client models.Client) error {
	_, exists := manager.Clients[id]
	if !exists {
		return models.ErrorEntityNotFound
	}

	manager.Clients[id] = client
	return nil
}

func (manager *InMemoryClientManager) Get(_ context.Context, id string) (models.Client, error) {
	client, exists := manager.Clients[id]
	if !exists {
		return models.Client{}, models.ErrorEntityNotFound
	}

	return client, nil
}

func (manager *InMemoryClientManager) Delete(_ context.Context, id string) error {
	delete(manager.Clients, id)
	return nil
}
