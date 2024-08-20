package storage

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ClientManager struct {
	Clients map[string]*goidc.Client
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		Clients: make(map[string]*goidc.Client),
	}
}

func (m *ClientManager) Save(
	_ context.Context,
	client *goidc.Client,
) error {
	m.Clients[client.ID] = client
	return nil
}

func (m *ClientManager) Get(
	_ context.Context,
	id string,
) (
	*goidc.Client,
	error,
) {
	client, exists := m.Clients[id]
	if !exists {
		return nil, errors.New("entity not found")
	}

	return client, nil
}

func (m *ClientManager) Delete(
	_ context.Context,
	id string,
) error {
	delete(m.Clients, id)
	return nil
}
