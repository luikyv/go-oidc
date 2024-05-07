package inmemory

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type InMemoryClientManager struct {
	clients map[string]models.Client
}

func NewInMemoryClientManager() *InMemoryClientManager {
	return &InMemoryClientManager{
		clients: make(map[string]models.Client),
	}
}

func (manager *InMemoryClientManager) Create(client models.Client) error {
	_, exists := manager.clients[client.Id]
	if exists {
		return issues.ErrorEntityAlreadyExists
	}

	manager.clients[client.Id] = client
	return nil
}

func (manager *InMemoryClientManager) Update(id string, client models.Client) error {
	_, exists := manager.clients[id]
	if !exists {
		return issues.ErrorEntityNotFound
	}

	manager.clients[id] = client
	return nil
}

func (manager *InMemoryClientManager) Get(id string) (models.Client, error) {
	client, exists := manager.clients[id]
	if !exists {
		return models.Client{}, issues.ErrorEntityNotFound
	}

	return client, nil
}

func (manager *InMemoryClientManager) Delete(id string) error {
	delete(manager.clients, id)
	return nil
}
