package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestCreateClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	client := goidc.Client{
		ID: "random_client_id",
	}

	// Then.
	err := manager.Create(context.Background(), client)

	// Assert.
	if err != nil {
		t.Error("error when creating the client", err)
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestCreateClient_ClientAlreadyExists(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	client := goidc.Client{
		ID: "random_client_id",
	}
	manager.Clients[client.ID] = client

	// Then.
	err := manager.Create(context.Background(), client)

	// Assert.
	if err == nil {
		t.Error("creating a client that already exists should return error")
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestUpdateClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	client := goidc.Client{
		ID: "random_client_id",
	}
	manager.Clients[client.ID] = client

	// Then.
	err := manager.Update(context.Background(), client.ID, client)

	// Assert.
	if err != nil {
		t.Error("error when updating the client", err)
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestUpdateClient_ClientDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()

	// Then.
	err := manager.Update(context.Background(), "invalid_client_id", goidc.Client{})

	// Assert.
	if err == nil {
		t.Error("updating a client that already exists shoud result in error")
	}
}

func TestGetClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	clientID := "random_client_id"
	manager.Clients[clientID] = goidc.Client{
		ID: clientID,
	}

	// Then.
	client, err := manager.Get(context.Background(), clientID)

	// Assert.
	if err != nil {
		t.Error("error when getting the client", err)
	}

	if client.ID != clientID {
		t.Error("invalid client ID")
	}
}

func TestGetClient_ClientDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	clientID := "random_client_id"

	// Then.
	_, err := manager.Get(context.Background(), clientID)

	// Assert.
	if err == nil {
		t.Error("getting a client that doesn't exist should result in error")
	}
}

func TestDeleteClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	clientID := "random_client_id"
	manager.Clients[clientID] = goidc.Client{
		ID: clientID,
	}

	// Then.
	err := manager.Delete(context.Background(), clientID)

	// Assert.
	if err != nil {
		t.Error("error when deleting the client", err)
	}

	if len(manager.Clients) != 0 {
		t.Error("there shouldn't be any clients")
	}
}

func TestDeleteClient_ClientDoesNotExist(t *testing.T) {
	// When.
	manager := inmemory.NewInMemoryClientManager()
	clientID := "random_client_id"

	// Then.
	err := manager.Delete(context.Background(), clientID)

	// Assert.
	if err != nil {
		t.Error("error when deleting the client", err)
	}
}
