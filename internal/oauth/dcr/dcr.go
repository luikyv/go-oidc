package dcr

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func CreateClient(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	models.OAuthError,
) {
	setCreationDefaults(ctx, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	if ctx.DcrPlugin != nil {
		ctx.DcrPlugin(ctx.RequestContext, &dynamicClient)
	}

	newClient := newClient(dynamicClient)
	if err := ctx.ClientManager.Create(newClient); err != nil {
		return models.DynamicClientResponse{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return models.DynamicClientResponse{
		Id:                      dynamicClient.Id,
		RegistrationUri:         getClientRegistrationUri(ctx, dynamicClient.Id),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func UpdateClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
	dynamicClient models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	models.OAuthError,
) {
	client, err := getProtectedClient(ctx, clientId, registrationAccessToken)
	if err != nil {
		return models.DynamicClientResponse{}, err
	}

	setUpdateDefaults(ctx, client, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	if ctx.DcrPlugin != nil {
		ctx.DcrPlugin(ctx.RequestContext, &dynamicClient)
	}

	updatedClient := newClient(dynamicClient)
	if err := ctx.ClientManager.Update(clientId, updatedClient); err != nil {
		return models.DynamicClientResponse{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return models.DynamicClientResponse{
		Id:                      dynamicClient.Id,
		RegistrationUri:         getClientRegistrationUri(ctx, dynamicClient.Id),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func GetClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
) (
	models.DynamicClientResponse,
	models.OAuthError,
) {

	client, err := getProtectedClient(ctx, clientId, registrationAccessToken)
	if err != nil {
		return models.DynamicClientResponse{}, err
	}

	return models.DynamicClientResponse{
		Id:              client.Id,
		RegistrationUri: getClientRegistrationUri(ctx, client.Id),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func DeleteClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
) models.OAuthError {
	_, err := getProtectedClient(ctx, clientId, registrationAccessToken)
	if err != nil {
		return err
	}

	if err := ctx.ClientManager.Delete(clientId); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}
	return nil
}
