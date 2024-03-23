package mock

import (
	"github.com/luikymagno/auth-server/internal/crud"
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

func (manager *MockedTokenSessionManager) Create(token models.Token, ch chan error) {
	_, exists := manager.Tokens[token.Id]
	if exists {
		ch <- issues.EntityAlreadyExistsError{Id: token.Id}
		return
	}

	manager.Tokens[token.Id] = token
	ch <- nil
}

func (manager *MockedTokenSessionManager) Get(id string, ch chan crud.TokenSessionGetResult) {
	token, exists := manager.Tokens[id]
	if !exists {
		ch <- crud.TokenSessionGetResult{
			Token: models.Token{},
			Error: issues.EntityNotFoundError{Id: id},
		}
		return
	}

	ch <- crud.TokenSessionGetResult{
		Token: token,
		Error: nil,
	}
}

func (manager *MockedTokenSessionManager) Delete(id string) {
	delete(manager.Tokens, id)
}
