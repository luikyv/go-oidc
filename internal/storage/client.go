package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ClientManager struct {
	Clients map[string]*goidc.Client
	mu      sync.RWMutex
	maxSize int
}

func NewClientManager(maxSize int) *ClientManager {
	return &ClientManager{
		Clients: make(map[string]*goidc.Client),
		maxSize: maxSize,
	}
}

func (m *ClientManager) Save(_ context.Context, c *goidc.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Clients) >= m.maxSize {
		removeOldest(m.Clients, func(c *goidc.Client) int {
			return c.CreatedAtTimestamp
		})
	}

	m.Clients[c.ID] = c
	return nil
}

func (m *ClientManager) Client(_ context.Context, id string) (*goidc.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, exists := m.Clients[id]
	if !exists {
		return nil, errors.New("entity not found")
	}

	// Make sure the content of jwks_uri is cleared from jwks when fetching the
	// client from the in memory storaged.
	if c.PublicJWKSURI != "" {
		c.PublicJWKS = goidc.JSONWebKeySet{}
	}

	return c, nil
}

func (m *ClientManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Clients, id)
	return nil
}

var _ goidc.ClientManager = NewClientManager(0)
