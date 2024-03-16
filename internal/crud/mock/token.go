package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type TokenSessionManager struct {
	tokens map[string]models.Token
}

func NewTokenSessionManager() *TokenSessionManager {
	return &TokenSessionManager{
		tokens: make(map[string]models.Token),
	}
}

func (manager *TokenSessionManager) Create(token models.Token) error {
	_, exists := manager.tokens[token.Id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: token.Id}
	}

	manager.tokens[token.Id] = token
	return nil
}

func (manager *TokenSessionManager) Get(id string) (models.Token, error) {
	token, exists := manager.tokens[id]
	if !exists {
		return models.Token{}, issues.EntityNotFoundError{Id: id}
	}

	return token, nil
}

func (manager *TokenSessionManager) Delete(id string) {
	delete(manager.tokens, id)
}
