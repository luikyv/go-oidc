package dcr

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func create(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) (
	dynamicClientResponse,
	oidc.Error,
) {
	if err := setCreationDefaults(ctx, &dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}

	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&dynamicClient.ClientMetaInfo)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}

	newClient := newClient(dynamicClient)
	if err := ctx.SaveClient(newClient); err != nil {
		return dynamicClientResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return dynamicClientResponse{
		ID:                      dynamicClient.ID,
		RegistrationURI:         registrationURI(ctx, dynamicClient.ID),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func setCreationDefaults(
	ctx *oidc.Context,
	dynamicClient *dynamicClientRequest,
) oidc.Error {
	id, err := clientID()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	dynamicClient.ID = id

	token, err := registrationAccessToken()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	dynamicClient.RegistrationAccessToken = token

	return setDefaults(ctx, dynamicClient)
}

func update(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) (
	dynamicClientResponse,
	oidc.Error,
) {
	client, err := protectedClient(ctx, dynamicClient)
	if err != nil {
		return dynamicClientResponse{}, err
	}

	if err := setUpdateDefaults(ctx, client, &dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&dynamicClient.ClientMetaInfo)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return dynamicClientResponse{}, err
	}

	updatedClient := newClient(dynamicClient)
	if err := ctx.SaveClient(updatedClient); err != nil {
		return dynamicClientResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	resp := dynamicClientResponse{
		ID:              dynamicClient.ID,
		RegistrationURI: registrationURI(ctx, dynamicClient.ID),
		Secret:          dynamicClient.Secret,
		ClientMetaInfo:  dynamicClient.ClientMetaInfo,
	}

	if ctx.ShouldRotateRegistrationTokens {
		resp.RegistrationAccessToken = dynamicClient.RegistrationAccessToken
	}

	return resp, nil
}

func setUpdateDefaults(
	ctx *oidc.Context,
	client *goidc.Client,
	dynamicClient *dynamicClientRequest,
) oidc.Error {
	dynamicClient.ID = client.ID
	if ctx.ShouldRotateRegistrationTokens {
		token, err := registrationAccessToken()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		dynamicClient.RegistrationAccessToken = token
	}

	return setDefaults(ctx, dynamicClient)
}

func client(
	ctx *oidc.Context,
	dynamicClientRequest dynamicClientRequest,
) (
	dynamicClientResponse,
	oidc.Error,
) {

	client, err := protectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return dynamicClientResponse{}, err
	}

	return dynamicClientResponse{
		ID:              client.ID,
		RegistrationURI: registrationURI(ctx, client.ID),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx *oidc.Context,
	dynamicClientRequest dynamicClientRequest,
) oidc.Error {
	_, err := protectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.ID); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	return nil
}
