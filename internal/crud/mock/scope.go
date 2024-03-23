package mock

import (
	"github.com/luikymagno/auth-server/internal/crud"
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

func (manager *MockedScopeManager) Create(scope models.Scope, ch chan error) {
	_, exists := manager.scopes[scope.Id]
	if exists {
		ch <- issues.EntityAlreadyExistsError{Id: scope.Id}
		return
	}

	manager.scopes[scope.Id] = scope
	ch <- nil
}

func (manager *MockedScopeManager) Update(id string, scope models.Scope, ch chan error) {
	_, exists := manager.scopes[id]
	if !exists {
		ch <- issues.EntityNotFoundError{Id: id}
		return
	}

	manager.scopes[id] = scope
	ch <- nil
}

func (manager *MockedScopeManager) Get(id string, ch chan crud.ScopeGetResult) {
	scope, exists := manager.scopes[id]
	if !exists {
		ch <- crud.ScopeGetResult{
			Scope: models.Scope{},
			Error: issues.EntityNotFoundError{Id: id},
		}
		return
	}

	ch <- crud.ScopeGetResult{
		Scope: scope,
		Error: nil,
	}
}

func (manager *MockedScopeManager) Delete(id string) {
	delete(manager.scopes, id)
}
