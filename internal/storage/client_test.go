package storage_test

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreateOrUpdateClient_HappyPath(t *testing.T) {
	// Given.
	manager := storage.NewClientManager(1)
	client := &goidc.Client{
		ID: "random_client_id",
	}

	// When.
	err := manager.Save(context.Background(), client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.Clients) != 1 {
		t.Errorf("len(manager.Clients) = %d, want 1", len(manager.Clients))
	}
}

func TestClient(t *testing.T) {
	// Given.
	manager := storage.NewClientManager(1)
	clientID := "random_client_id"
	manager.Clients[clientID] = &goidc.Client{
		ID: clientID,
	}

	// When.
	client, err := manager.Client(context.Background(), clientID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.ID != clientID {
		t.Errorf("ID = %s, want %s", client.ID, clientID)
	}
}

func TestClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := storage.NewClientManager(1)
	clientID := "random_client_id"

	// When.
	_, err := manager.Client(context.Background(), clientID)

	// Then.
	if err == nil {
		t.Errorf("the client should not be found")
	}
}

func TestDeleteClient(t *testing.T) {
	// Given.
	manager := storage.NewClientManager(1)
	clientID := "random_client_id"
	manager.Clients[clientID] = &goidc.Client{
		ID: clientID,
	}

	// When.
	err := manager.Delete(context.Background(), clientID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.Clients) != 0 {
		t.Errorf("len(manager.Clients) = %d, want 0", len(manager.Clients))
	}
}

func TestDeleteClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := storage.NewClientManager(1)
	clientID := "random_client_id"

	// When.
	err := manager.Delete(context.Background(), clientID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
