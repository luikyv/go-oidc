package mock

import (
	"github.com/luikymagno/auth-server/internal/crud"
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

func (manager *MockedTokenModelManager) Create(model models.TokenModel, ch chan error) {
	opaqueModel, _ := model.(models.OpaqueTokenModel)
	_, exists := manager.models[opaqueModel.Id]
	if exists {
		ch <- issues.EntityAlreadyExistsError{Id: opaqueModel.Id}
		return
	}

	manager.models[opaqueModel.Id] = model
	ch <- nil
}

func (manager *MockedTokenModelManager) Update(id string, model models.TokenModel, ch chan error) {
	opaqueModel, _ := model.(models.OpaqueTokenModel)
	_, exists := manager.models[id]
	if !exists {
		ch <- issues.EntityNotFoundError{Id: id}
		return
	}

	manager.models[id] = opaqueModel
	ch <- nil
}

func (manager *MockedTokenModelManager) Get(id string, ch chan crud.TokenModelGetResult) {
	model, exists := manager.models[id]
	if !exists {
		ch <- crud.TokenModelGetResult{
			TokenModel: nil,
			Error:      issues.EntityNotFoundError{Id: id},
		}
		return
	}

	ch <- crud.TokenModelGetResult{
		TokenModel: model,
		Error:      nil,
	}
}

func (manager *MockedTokenModelManager) Delete(id string) {
	delete(manager.models, id)
}
