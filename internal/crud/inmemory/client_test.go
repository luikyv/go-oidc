package inmemory_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
)

func TestCreateClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	client := models.Client{
		Id: "random_client_id",
	}

	// Then.
	err := manager.Create(client)

	// Assert.
	if err != nil {
		t.Error("error when creating the client", err)
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestCreateClient_ClientAlreadyExists(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	client := models.Client{
		Id: "random_client_id",
	}
	manager.Clients[client.Id] = client

	// Then.
	err := manager.Create(client)

	// Assert.
	if err == nil {
		t.Error("creating a client that already exists should return error")
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestUpdateClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	client := models.Client{
		Id: "random_client_id",
	}
	manager.Clients[client.Id] = client

	// Then.
	err := manager.Update(client.Id, client)

	// Assert.
	if err != nil {
		t.Error("error when updating the client", err)
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestUpdateClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()

	// Then.
	err := manager.Update("invalid_client_id", models.Client{})

	// Assert.
	if err == nil {
		t.Error("updating a client that already exists shoud result in error")
	}
}

func TestGetClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	clientId := "random_client_id"
	manager.Clients[clientId] = models.Client{
		Id: clientId,
	}

	// Then.
	client, err := manager.Get(clientId)

	// Assert.
	if err != nil {
		t.Error("error when getting the client", err)
	}

	if client.Id != clientId {
		t.Error("invalid client ID")
	}
}

func TestGetClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	clientId := "random_client_id"

	// Then.
	_, err := manager.Get(clientId)

	// Assert.
	if err == nil {
		t.Error("getting a client that doesn't exist should result in error")
	}
}

func TestDeleteClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	clientId := "random_client_id"
	manager.Clients[clientId] = models.Client{
		Id: clientId,
	}

	// Then.
	err := manager.Delete(clientId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the client", err)
	}

	if len(manager.Clients) != 0 {
		t.Error("there shouldn't be any clients")
	}
}

func TestDeleteClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewInMemoryClientManager()
	clientId := "random_client_id"

	// Then.
	err := manager.Delete(clientId)

	// Assert.
	if err != nil {
		t.Error("error when deleting the client", err)
	}
}
