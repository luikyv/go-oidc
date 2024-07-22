package inmemory_test

import (
	"context"
	"testing"

	"github.com/luikyv/goidc/internal/crud/inmemory"
	"github.com/luikyv/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOrUpdateClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewClientManager()
	client := &goidc.Client{
		ID: "random_client_id",
	}

	// When.
	err := manager.CreateOrUpdate(context.Background(), client)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Clients, 1, "there should be exactly one client")
}

func TestGetClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewClientManager()
	clientID := "random_client_id"
	manager.Clients[clientID] = &goidc.Client{
		ID: clientID,
	}

	// When.
	client, err := manager.Get(context.Background(), clientID)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, clientID, client.ID, "invalid client ID")
}

func TestGetClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewClientManager()
	clientID := "random_client_id"

	// When.
	_, err := manager.Get(context.Background(), clientID)

	// Then.
	assert.NotNil(t, err)
}

func TestDeleteClient_HappyPath(t *testing.T) {
	// Given.
	manager := inmemory.NewClientManager()
	clientID := "random_client_id"
	manager.Clients[clientID] = &goidc.Client{
		ID: clientID,
	}

	// When.
	err := manager.Delete(context.Background(), clientID)

	// Then.
	require.Nil(t, err)
	assert.Len(t, manager.Clients, 0, "there shouldn't be any clients")
}

func TestDeleteClient_ClientDoesNotExist(t *testing.T) {
	// Given.
	manager := inmemory.NewClientManager()
	clientID := "random_client_id"

	// When.
	err := manager.Delete(context.Background(), clientID)

	// Then.
	require.Nil(t, err)
}
