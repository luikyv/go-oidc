package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type MockedClientManager struct {
	clients map[string]models.Client
}

func NewMockedClientManager() *MockedClientManager {
	return &MockedClientManager{
		clients: make(map[string]models.Client),
	}
}

func (manager *MockedClientManager) Create(client models.Client) error {
	_, exists := manager.clients[client.Id]
	if exists {
		return issues.ErrorEntityAlreadyExists
	}

	manager.clients[client.Id] = client
	return nil
}

func (manager *MockedClientManager) Update(id string, client models.Client) error {
	_, exists := manager.clients[id]
	if !exists {
		return issues.ErrorEntityNotFound
	}

	manager.clients[id] = client
	return nil
}

func (manager *MockedClientManager) Get(id string) (models.Client, error) {
	client, exists := manager.clients[id]
	if !exists {
		return models.Client{}, issues.ErrorEntityNotFound
	}

	return client, nil
}

func (manager *MockedClientManager) Delete(id string) error {
	delete(manager.clients, id)
	return nil
}
