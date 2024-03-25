package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type MockedScopeManager struct {
	scopes map[string]models.Scope
}

func NewMockedScopeManager() *MockedScopeManager {
	return &MockedScopeManager{
		scopes: make(map[string]models.Scope),
	}
}

func (manager *MockedScopeManager) Create(scope models.Scope) error {
	_, exists := manager.scopes[scope.Id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: scope.Id}
	}

	manager.scopes[scope.Id] = scope
	return nil
}

func (manager *MockedScopeManager) Update(id string, scope models.Scope) error {
	_, exists := manager.scopes[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.scopes[id] = scope
	return nil
}

func (manager *MockedScopeManager) Get(id string) (models.Scope, error) {
	scope, exists := manager.scopes[id]
	if !exists {
		return models.Scope{}, issues.EntityNotFoundError{Id: id}
	}

	return scope, nil
}

func (manager *MockedScopeManager) Delete(id string) error {
	delete(manager.scopes, id)
	return nil
}
