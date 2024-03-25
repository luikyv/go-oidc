package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type MockedTokenSessionManager struct {
	Tokens map[string]models.Token
}

func NewMockedTokenSessionManager() *MockedTokenSessionManager {
	return &MockedTokenSessionManager{
		Tokens: make(map[string]models.Token),
	}
}

func (manager *MockedTokenSessionManager) Create(token models.Token) error {
	_, exists := manager.Tokens[token.Id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: token.Id}
	}

	manager.Tokens[token.Id] = token
	return nil
}

func (manager *MockedTokenSessionManager) Get(id string) (models.Token, error) {
	token, exists := manager.Tokens[id]
	if !exists {
		return models.Token{}, issues.EntityNotFoundError{Id: id}
	}

	return token, nil
}

func (manager *MockedTokenSessionManager) Delete(id string) error {
	delete(manager.Tokens, id)
	return nil
}
