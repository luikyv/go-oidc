package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type MockedGrantModelManager struct {
	models map[string]models.GrantModel
}

func NewMockedGrantModelManager() *MockedGrantModelManager {
	return &MockedGrantModelManager{
		models: make(map[string]models.GrantModel),
	}
}

func (manager *MockedGrantModelManager) Create(grantModel models.GrantModel) error {

	_, exists := manager.models[grantModel.Meta.Id]
	if exists {
		return issues.ErrorEntityAlreadyExists
	}

	manager.models[grantModel.Meta.Id] = grantModel
	return nil
}

func (manager *MockedGrantModelManager) Update(id string, model models.GrantModel) error {
	_, exists := manager.models[id]
	if !exists {
		return issues.ErrorEntityNotFound
	}

	manager.models[id] = model
	return nil
}

func (manager *MockedGrantModelManager) Get(id string) (models.GrantModel, error) {
	model, exists := manager.models[id]
	if !exists {
		return models.GrantModel{}, issues.ErrorEntityNotFound
	}

	return model, nil
}

func (manager *MockedGrantModelManager) Delete(id string) error {
	delete(manager.models, id)
	return nil
}
