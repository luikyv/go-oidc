package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestCreateOrUpdateClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewClientManager()
	client := goidc.Client{
		ID: "random_client_id",
	}

	// Then.
	err := manager.CreateOrUpdate(context.Background(), client)

	// Assert.
	if err != nil {
		t.Error("error when creating the client", err)
	}

	if len(manager.Clients) != 1 {
		t.Error("there should be exactly one client")
	}
}

func TestGetClient_HappyPath(t *testing.T) {
	// When.
	manager := inmemory.NewClientManager()
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
	manager := inmemory.NewClientManager()
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
	manager := inmemory.NewClientManager()
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
	manager := inmemory.NewClientManager()
	clientID := "random_client_id"

	// Then.
	err := manager.Delete(context.Background(), clientID)

	// Assert.
	if err != nil {
		t.Error("error when deleting the client", err)
	}
}
