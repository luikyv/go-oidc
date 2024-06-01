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

	ctx.ExecureDcrPlugin(&dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
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
	dynamicClient models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	models.OAuthError,
) {
	client, err := getProtectedClient(ctx, dynamicClient)
	if err != nil {
		return models.DynamicClientResponse{}, err
	}

	setUpdateDefaults(ctx, client, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	ctx.ExecureDcrPlugin(&dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	updatedClient := newClient(dynamicClient)
	if err := ctx.ClientManager.Update(client.Id, updatedClient); err != nil {
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
	dynamicClientRequest models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	models.OAuthError,
) {

	client, err := getProtectedClient(ctx, dynamicClientRequest)
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
	dynamicClientRequest models.DynamicClientRequest,
) models.OAuthError {
	_, err := getProtectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.ClientManager.Delete(dynamicClientRequest.Id); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}
	return nil
}
