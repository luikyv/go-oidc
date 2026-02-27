package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type TokenManager struct {
	Tokens  map[string]*goidc.Token
	mu      sync.RWMutex
	maxSize int
}

func NewTokenManager(maxSize int) *TokenManager {
	return &TokenManager{
		Tokens:  make(map[string]*goidc.Token),
		maxSize: maxSize,
	}
}

func (m *TokenManager) Save(_ context.Context, token *goidc.Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Tokens) >= m.maxSize {
		removeOldest(m.Tokens, func(t *goidc.Token) int {
			return t.CreatedAtTimestamp
		})
	}

	m.Tokens[token.ID] = token
	return nil
}

func (m *TokenManager) TokenByID(_ context.Context, id string) (*goidc.Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.Tokens[id]
	if !exists {
		return nil, errors.New("entity not found")
	}

	return token, nil
}

func (m *TokenManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Tokens, id)
	return nil
}

func (m *TokenManager) DeleteByGrantID(_ context.Context, grantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, token := range m.Tokens {
		if token.GrantID == grantID {
			delete(m.Tokens, id)
		}
	}

	return nil
}

var _ goidc.TokenManager = NewTokenManager(0)
