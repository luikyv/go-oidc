package session

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type TokenSessionManager interface {
	Create(token models.Token) error
	Get(id string) (models.Token, error)
	Delete(id string)
}

type InMemoryTokenSessionManager struct {
	tokens map[string]models.Token
}

func NewInMemoryTokenSessionManager() *InMemoryTokenSessionManager {
	return &InMemoryTokenSessionManager{
		tokens: make(map[string]models.Token),
	}
}

func (manager *InMemoryTokenSessionManager) Create(token models.Token) error {
	_, exists := manager.tokens[token.Id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: token.Id}
	}

	manager.tokens[token.Id] = token
	return nil
}

func (manager *InMemoryTokenSessionManager) Get(id string) (models.Token, error) {
	token, exists := manager.tokens[id]
	if !exists {
		return models.Token{}, issues.EntityNotFoundError{Id: id}
	}

	return token, nil
}

func (manager *InMemoryTokenSessionManager) Delete(id string) {
	delete(manager.tokens, id)
}
