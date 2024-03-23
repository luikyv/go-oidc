package mock

import (
	"github.com/luikymagno/auth-server/internal/crud"
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

func (manager *MockedClientManager) Create(client models.Client, ch chan error) {
	_, exists := manager.clients[client.Id]
	if exists {
		ch <- issues.EntityAlreadyExistsError{Id: client.Id}
		return
	}

	manager.clients[client.Id] = client
	ch <- nil
}

func (manager *MockedClientManager) Update(id string, client models.Client, ch chan error) {
	_, exists := manager.clients[id]
	if !exists {
		ch <- issues.EntityNotFoundError{Id: id}
		return
	}

	manager.clients[id] = client
	ch <- nil
}

func (manager *MockedClientManager) Get(id string, ch chan crud.ClientGetResult) {
	client, exists := manager.clients[id]
	if !exists {
		ch <- crud.ClientGetResult{
			Client: models.Client{},
			Error:  issues.EntityNotFoundError{Id: id},
		}
		return
	}

	ch <- crud.ClientGetResult{
		Client: client,
		Error:  nil,
	}
}

func (manager *MockedClientManager) Delete(id string) {
	delete(manager.clients, id)
}
