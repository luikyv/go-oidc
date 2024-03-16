package crud

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type ClientManager interface {
	Create(client models.Client) error
	Update(id string, client models.Client) error
	Get(id string) (models.Client, error)
	Delete(id string)
}

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
		return issues.EntityAlreadyExistsError{Id: client.Id}
	}

	manager.clients[client.Id] = client
	return nil
}

func (manager *InMemoryClientManager) Update(id string, client models.Client) error {
	_, exists := manager.clients[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.clients[id] = client
	return nil
}

func (manager *InMemoryClientManager) Get(id string) (models.Client, error) {
	client, exists := manager.clients[id]
	if !exists {
		return models.Client{}, issues.EntityNotFoundError{Id: id}
	}

	return client, nil
}

func (manager *InMemoryClientManager) Delete(id string) {
	delete(manager.clients, id)
}
