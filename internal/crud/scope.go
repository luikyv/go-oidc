package crud

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type ScopeManager interface {
	Create(scope models.Scope) error
	Update(id string, scope models.Scope) error
	Get(id string) (models.Scope, error)
	Delete(id string)
}

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
		return issues.EntityAlreadyExistsError{Id: scope.Id}
	}

	manager.scopes[scope.Id] = scope
	return nil
}

func (manager *InMemoryScopeManager) Update(id string, scope models.Scope) error {
	_, exists := manager.scopes[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.scopes[id] = scope
	return nil
}

func (manager *InMemoryScopeManager) Get(id string) (models.Scope, error) {
	scope, exists := manager.scopes[id]
	if !exists {
		return models.Scope{}, issues.EntityNotFoundError{Id: id}
	}

	return scope, nil
}

func (manager *InMemoryScopeManager) Delete(id string) {
	delete(manager.scopes, id)
}
