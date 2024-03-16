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
		return issues.EntityAlreadyExistsError{Id: client.Id}
	}

	manager.clients[client.Id] = client
	return nil
}

func (manager *MockedClientManager) Update(id string, client models.Client) error {
	_, exists := manager.clients[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.clients[id] = client
	return nil
}

func (manager *MockedClientManager) Get(id string) (models.Client, error) {
	client, exists := manager.clients[id]
	if !exists {
		return models.Client{}, issues.EntityNotFoundError{Id: id}
	}

	return client, nil
}

func (manager *MockedClientManager) Delete(id string) {
	delete(manager.clients, id)
}
