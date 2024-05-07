package inmemory

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type InMemoryGrantModelManager struct {
	models map[string]models.GrantModel
}

func NewInMemoryGrantModelManager() *InMemoryGrantModelManager {
	return &InMemoryGrantModelManager{
		models: make(map[string]models.GrantModel),
	}
}

func (manager *InMemoryGrantModelManager) Create(grantModel models.GrantModel) error {

	_, exists := manager.models[grantModel.Meta.Id]
	if exists {
		return issues.ErrorEntityAlreadyExists
	}

	manager.models[grantModel.Meta.Id] = grantModel
	return nil
}

func (manager *InMemoryGrantModelManager) Update(id string, model models.GrantModel) error {
	_, exists := manager.models[id]
	if !exists {
		return issues.ErrorEntityNotFound
	}

	manager.models[id] = model
	return nil
}

func (manager *InMemoryGrantModelManager) Get(id string) (models.GrantModel, error) {
	model, exists := manager.models[id]
	if !exists {
		return models.GrantModel{}, issues.ErrorEntityNotFound
	}

	return model, nil
}

func (manager *InMemoryGrantModelManager) Delete(id string) error {
	delete(manager.models, id)
	return nil
}
