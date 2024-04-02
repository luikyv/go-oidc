package mock

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type MockedTokenModelManager struct {
	models map[string]models.TokenModel
}

func NewMockedTokenModelManager() *MockedTokenModelManager {
	return &MockedTokenModelManager{
		models: make(map[string]models.TokenModel),
	}
}

func (manager *MockedTokenModelManager) Create(tokenModel models.TokenModel) error {

	var id string
	switch tm := tokenModel.(type) {
	case models.OpaqueTokenModel:
	case models.JWTTokenModel:
		id = tm.Id
	}

	_, exists := manager.models[id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: id}
	}

	manager.models[id] = tokenModel
	return nil
}

func (manager *MockedTokenModelManager) Update(id string, model models.TokenModel) error {
	_, exists := manager.models[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.models[id] = model
	return nil
}

func (manager *MockedTokenModelManager) Get(id string) (models.TokenModel, error) {
	model, exists := manager.models[id]
	if !exists {
		return nil, issues.EntityNotFoundError{Id: id}
	}

	return model, nil
}

func (manager *MockedTokenModelManager) Delete(id string) error {
	delete(manager.models, id)
	return nil
}
