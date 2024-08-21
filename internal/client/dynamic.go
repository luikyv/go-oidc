package client

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func create(
	ctx *oidc.Context,
	req DynamicClientRequest,
) (
	DynamicClientResponse,
	oidc.Error,
) {
	if err := setCreationDefaults(ctx, &req); err != nil {
		return DynamicClientResponse{}, err
	}

	if err := validateDynamicClientRequest(ctx, req); err != nil {
		return DynamicClientResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&req.ClientMetaInfo)
	if err := validateDynamicClientRequest(ctx, req); err != nil {
		return DynamicClientResponse{}, err
	}

	newClient := newClient(req)
	if err := ctx.SaveClient(newClient); err != nil {
		return DynamicClientResponse{}, err
	}

	return DynamicClientResponse{
		ID:                      req.ID,
		RegistrationURI:         registrationURI(ctx, req.ID),
		RegistrationAccessToken: req.RegistrationAccessToken,
		Secret:                  req.Secret,
		ClientMetaInfo:          req.ClientMetaInfo,
	}, nil
}

func setCreationDefaults(
	ctx *oidc.Context,
	req *DynamicClientRequest,
) oidc.Error {
	id, err := clientID()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not generate the client id")
	}
	req.ID = id

	token, err := registrationAccessToken()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not generate the registration access token")
	}
	req.RegistrationAccessToken = token

	return setDefaults(ctx, req)
}

func update(
	ctx *oidc.Context,
	dc DynamicClientRequest,
) (
	DynamicClientResponse,
	oidc.Error,
) {
	c, err := protected(ctx, dc)
	if err != nil {
		return DynamicClientResponse{}, err
	}

	if err := setUpdateDefaults(ctx, c, &dc); err != nil {
		return DynamicClientResponse{}, err
	}
	if err := validateDynamicClientRequest(ctx, dc); err != nil {
		return DynamicClientResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&dc.ClientMetaInfo)
	if err := validateDynamicClientRequest(ctx, dc); err != nil {
		return DynamicClientResponse{}, err
	}

	updatedClient := newClient(dc)
	if err := ctx.SaveClient(updatedClient); err != nil {
		return DynamicClientResponse{}, err
	}

	resp := DynamicClientResponse{
		ID:              dc.ID,
		RegistrationURI: registrationURI(ctx, dc.ID),
		Secret:          dc.Secret,
		ClientMetaInfo:  dc.ClientMetaInfo,
	}

	if ctx.DCR.TokenRotationIsEnabled {
		resp.RegistrationAccessToken = dc.RegistrationAccessToken
	}

	return resp, nil
}

func setUpdateDefaults(
	ctx *oidc.Context,
	client *goidc.Client,
	dynamicClient *DynamicClientRequest,
) oidc.Error {
	dynamicClient.ID = client.ID
	if ctx.DCR.TokenRotationIsEnabled {
		token, err := registrationAccessToken()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError,
				"could not generate the registration access token")
		}
		dynamicClient.RegistrationAccessToken = token
	}

	return setDefaults(ctx, dynamicClient)
}

func fetch(
	ctx *oidc.Context,
	dynamicClientRequest DynamicClientRequest,
) (
	DynamicClientResponse,
	oidc.Error,
) {

	client, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return DynamicClientResponse{}, err
	}

	return DynamicClientResponse{
		ID:              client.ID,
		RegistrationURI: registrationURI(ctx, client.ID),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx *oidc.Context,
	dynamicClientRequest DynamicClientRequest,
) oidc.Error {
	_, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.ID); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not delete the client")
	}
	return nil
}

func setDefaults(ctx *oidc.Context, dynamicClient *DynamicClientRequest) oidc.Error {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientAuthnSecretBasic
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		secret, err := clientSecret()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError,
				"could not generate the client secret")
		}
		dynamicClient.Secret = secret
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	}

	if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" && dynamicClient.IDTokenContentEncryptionAlgorithm == "" {
		dynamicClient.IDTokenContentEncryptionAlgorithm = ctx.User.DefaultContentEncryptionAlgorithm
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && dynamicClient.UserInfoContentEncryptionAlgorithm == "" {
		dynamicClient.UserInfoContentEncryptionAlgorithm = ctx.User.DefaultContentEncryptionAlgorithm
	}

	if dynamicClient.JARMKeyEncryptionAlgorithm != "" && dynamicClient.JARMContentEncryptionAlgorithm == "" {
		dynamicClient.JARMContentEncryptionAlgorithm = ctx.JARM.DefaultContentEncryptionAlgorithm
	}

	if dynamicClient.JARKeyEncryptionAlgorithm != "" && dynamicClient.JARContentEncryptionAlgorithm == "" {
		dynamicClient.JARContentEncryptionAlgorithm = ctx.JAR.DefaultContentEncryptionAlgorithm
	}

	if dynamicClient.CustomAttributes == nil {
		dynamicClient.CustomAttributes = make(map[string]any)
	}

	return nil
}

func newClient(dynamicClient DynamicClientRequest) *goidc.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.RegistrationAccessToken), bcrypt.DefaultCost)
	client := &goidc.Client{
		ID:                            dynamicClient.ID,
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                dynamicClient.ClientMetaInfo,
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost || dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.Secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		client.Secret = dynamicClient.Secret
	}

	return client
}

func registrationURI(ctx *oidc.Context, clientID string) string {
	return ctx.BaseURL() + ctx.Endpoint.DCR + "/" + clientID
}

func protected(
	ctx *oidc.Context,
	dynamicClient DynamicClientRequest,
) (
	*goidc.Client,
	oidc.Error,
) {
	if dynamicClient.ID == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	client, err := ctx.Client(dynamicClient.ID)
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "could not load the client")
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return nil, oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid token")
	}

	return client, nil
}

func clientID() (string, error) {
	id, err := strutil.Random(idLength)
	if err != nil {
		return "", err
	}
	return "dc-" + id, nil
}

func clientSecret() (string, error) {
	return strutil.Random(secretLength)
}

func registrationAccessToken() (string, error) {
	return strutil.Random(registrationAccessTokenLength)
}
