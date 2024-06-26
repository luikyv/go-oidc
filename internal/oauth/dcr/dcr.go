package dcr

import (
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func CreateClient(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) (
	models.DynamicClientResponse,
	goidc.OAuthError,
) {
	setCreationDefaults(ctx, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	ctx.ExecuteDcrPlugin(&dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	newClient := newClient(dynamicClient)
	if err := ctx.CreateClient(newClient); err != nil {
		return models.DynamicClientResponse{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
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
	dynamicClient goidc.DynamicClient,
) (
	models.DynamicClientResponse,
	goidc.OAuthError,
) {
	client, err := getProtectedClient(ctx, dynamicClient)
	if err != nil {
		return models.DynamicClientResponse{}, err
	}

	setUpdateDefaults(ctx, client, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	ctx.ExecuteDcrPlugin(&dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	updatedClient := newClient(dynamicClient)
	if err := ctx.UpdateClient(client.Id, updatedClient); err != nil {
		return models.DynamicClientResponse{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
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
	dynamicClientRequest goidc.DynamicClient,
) (
	models.DynamicClientResponse,
	goidc.OAuthError,
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
	dynamicClientRequest goidc.DynamicClient,
) goidc.OAuthError {
	_, err := getProtectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.Id); err != nil {
		return goidc.NewOAuthError(goidc.InternalError, err.Error())
	}
	return nil
}
