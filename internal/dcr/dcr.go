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
	goidc.OAuthError,
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
		return dynamicClientResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return dynamicClientResponse{
		ID:                      dynamicClient.ID,
		RegistrationURI:         getClientRegistrationURI(ctx, dynamicClient.ID),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func update(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) (
	dynamicClientResponse,
	goidc.OAuthError,
) {
	client, err := getProtectedClient(ctx, dynamicClient)
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
		return dynamicClientResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	resp := dynamicClientResponse{
		ID:              dynamicClient.ID,
		RegistrationURI: getClientRegistrationURI(ctx, dynamicClient.ID),
		Secret:          dynamicClient.Secret,
		ClientMetaInfo:  dynamicClient.ClientMetaInfo,
	}

	if ctx.ShouldRotateRegistrationTokens {
		resp.RegistrationAccessToken = dynamicClient.RegistrationAccessToken
	}

	return resp, nil
}

func client(
	ctx *oidc.Context,
	dynamicClientRequest dynamicClientRequest,
) (
	dynamicClientResponse,
	goidc.OAuthError,
) {

	client, err := getProtectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return dynamicClientResponse{}, err
	}

	return dynamicClientResponse{
		ID:              client.ID,
		RegistrationURI: getClientRegistrationURI(ctx, client.ID),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx *oidc.Context,
	dynamicClientRequest dynamicClientRequest,
) goidc.OAuthError {
	_, err := getProtectedClient(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.ID); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	return nil
}
