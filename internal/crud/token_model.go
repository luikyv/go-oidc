package crud

import (
	issues "github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

type TokenModelManager interface {
	Create(model models.TokenModel) error
	Update(id string, model models.TokenModel) error
	Get(id string) (models.TokenModel, error)
	Delete(id string)
}

type InMemoryTokenModelManager struct {
	models map[string]models.TokenModel
}

func NewInMemoryTokenModelManager() *InMemoryTokenModelManager {
	return &InMemoryTokenModelManager{
		models: make(map[string]models.TokenModel),
	}
}

func (manager *InMemoryTokenModelManager) Create(model models.TokenModel) error {
	opaqueModel, _ := model.(models.OpaqueTokenModel)
	_, exists := manager.models[opaqueModel.Id]
	if exists {
		return issues.EntityAlreadyExistsError{Id: opaqueModel.Id}
	}

	manager.models[opaqueModel.Id] = model
	return nil
}

func (manager *InMemoryTokenModelManager) Update(id string, model models.TokenModel) error {
	opaqueModel, _ := model.(models.OpaqueTokenModel)
	_, exists := manager.models[id]
	if !exists {
		return issues.EntityNotFoundError{Id: id}
	}

	manager.models[id] = opaqueModel
	return nil
}

func (manager *InMemoryTokenModelManager) Get(id string) (models.TokenModel, error) {
	model, exists := manager.models[id]
	if !exists {
		return nil, issues.EntityNotFoundError{Id: id}
	}

	return model, nil
}

func (manager *InMemoryTokenModelManager) Delete(id string) {
	delete(manager.models, id)
}
