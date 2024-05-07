package inmemory

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type InMemoryScopeManager struct {
	scopes map[string]models.Scope
}

func NewInMemoryScopeManager() *InMemoryScopeManager {
	return &InMemoryScopeManager{
		scopes: make(map[string]models.Scope),
	}
}

func (manager *InMemoryScopeManager) Create(scope models.Scope) error {
	_, exists := manager.scopes[scope.Id]
	if exists {
		return issues.ErrorEntityAlreadyExists
	}

	manager.scopes[scope.Id] = scope
	return nil
}

func (manager *InMemoryScopeManager) Update(id string, scope models.Scope) error {
	_, exists := manager.scopes[id]
	if !exists {
		return issues.ErrorEntityNotFound
	}

	manager.scopes[id] = scope
	return nil
}

func (manager *InMemoryScopeManager) Get(id string) (models.Scope, error) {
	scope, exists := manager.scopes[id]
	if !exists {
		return models.Scope{}, issues.ErrorEntityNotFound
	}

	return scope, nil
}

func (manager *InMemoryScopeManager) Delete(id string) error {
	delete(manager.scopes, id)
	return nil
}
