package client

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func create(
	ctx *oidc.Context,
	req dynamicRequest,
) (
	dynamicResponse,
	oidc.Error,
) {
	if err := setCreationDefaults(ctx, &req); err != nil {
		return dynamicResponse{}, err
	}

	if err := validateDynamicRequest(ctx, req); err != nil {
		return dynamicResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&req.ClientMetaInfo)
	if err := validateDynamicRequest(ctx, req); err != nil {
		return dynamicResponse{}, err
	}

	newClient := newClient(req)
	if err := ctx.SaveClient(newClient); err != nil {
		return dynamicResponse{}, err
	}

	return dynamicResponse{
		ID:                      req.id,
		RegistrationURI:         registrationURI(ctx, req.id),
		RegistrationAccessToken: req.registrationAccessToken,
		Secret:                  req.secret,
		ClientMetaInfo:          req.ClientMetaInfo,
	}, nil
}

func setCreationDefaults(
	ctx *oidc.Context,
	req *dynamicRequest,
) oidc.Error {
	id, err := clientID()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not generate the client id")
	}
	req.id = id

	token, err := registrationAccessToken()
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not generate the registration access token")
	}
	req.registrationAccessToken = token

	return setDefaults(ctx, req)
}

func update(
	ctx *oidc.Context,
	dc dynamicRequest,
) (
	dynamicResponse,
	oidc.Error,
) {
	c, err := protected(ctx, dc)
	if err != nil {
		return dynamicResponse{}, err
	}

	if err := setUpdateDefaults(ctx, c, &dc); err != nil {
		return dynamicResponse{}, err
	}
	if err := validateDynamicRequest(ctx, dc); err != nil {
		return dynamicResponse{}, err
	}

	ctx.ExecuteDCRPlugin(&dc.ClientMetaInfo)
	if err := validateDynamicRequest(ctx, dc); err != nil {
		return dynamicResponse{}, err
	}

	updatedClient := newClient(dc)
	if err := ctx.SaveClient(updatedClient); err != nil {
		return dynamicResponse{}, err
	}

	resp := dynamicResponse{
		ID:              dc.id,
		RegistrationURI: registrationURI(ctx, dc.id),
		Secret:          dc.secret,
		ClientMetaInfo:  dc.ClientMetaInfo,
	}

	if ctx.DCR.TokenRotationIsEnabled {
		resp.RegistrationAccessToken = dc.registrationAccessToken
	}

	return resp, nil
}

func setUpdateDefaults(
	ctx *oidc.Context,
	client *goidc.Client,
	dynamicClient *dynamicRequest,
) oidc.Error {
	dynamicClient.id = client.ID
	if ctx.DCR.TokenRotationIsEnabled {
		token, err := registrationAccessToken()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError,
				"could not generate the registration access token")
		}
		dynamicClient.registrationAccessToken = token
	}

	return setDefaults(ctx, dynamicClient)
}

func fetch(
	ctx *oidc.Context,
	dynamicClientRequest dynamicRequest,
) (
	dynamicResponse,
	oidc.Error,
) {

	client, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return dynamicResponse{}, err
	}

	return dynamicResponse{
		ID:              client.ID,
		RegistrationURI: registrationURI(ctx, client.ID),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func remove(
	ctx *oidc.Context,
	dynamicClientRequest dynamicRequest,
) oidc.Error {
	_, err := protected(ctx, dynamicClientRequest)
	if err != nil {
		return err
	}

	if err := ctx.DeleteClient(dynamicClientRequest.id); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError,
			"could not delete the client")
	}
	return nil
}

func setDefaults(ctx *oidc.Context, dynamicClient *dynamicRequest) oidc.Error {
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
		dynamicClient.secret = secret
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

func newClient(dynamicClient dynamicRequest) *goidc.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.registrationAccessToken), bcrypt.DefaultCost)
	client := &goidc.Client{
		ID:                            dynamicClient.id,
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                dynamicClient.ClientMetaInfo,
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost || dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		client.Secret = dynamicClient.secret
	}

	return client
}

func registrationURI(ctx *oidc.Context, clientID string) string {
	return ctx.BaseURL() + ctx.Endpoint.DCR + "/" + clientID
}

func protected(
	ctx *oidc.Context,
	dynamicClient dynamicRequest,
) (
	*goidc.Client,
	oidc.Error,
) {
	if dynamicClient.id == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	client, err := ctx.Client(dynamicClient.id)
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "could not load the client")
	}

	if dynamicClient.registrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.registrationAccessToken) {
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
