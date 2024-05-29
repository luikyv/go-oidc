package dcr

import (
	"strings"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func setDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = constants.ClientSecretBasicAuthn
	}

	if dynamicClient.AuthnMethod == constants.ClientSecretPostAuthn ||
		dynamicClient.AuthnMethod == constants.ClientSecretBasicAuthn ||
		dynamicClient.AuthnMethod == constants.ClientSecretJwt {
		dynamicClient.Secret = unit.GenerateClientSecret()
	}

	if dynamicClient.Scopes == "" {
		dynamicClient.Scopes = strings.Join(ctx.Scopes, " ")
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []constants.ResponseType{constants.CodeResponse}
	}
}

func setCreationDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	dynamicClient.Id = unit.GenerateClientId()
	dynamicClient.RegistrationAccessToken = unit.GenerateRegistrationAccessToken()
	setDefaults(ctx, dynamicClient)
}

func setUpdateDefaults(
	ctx utils.Context,
	client models.Client,
	dynamicClient *models.DynamicClientRequest,
) {
	dynamicClient.Id = client.Id
	if ctx.ShouldRotateRegistrationTokens {
		dynamicClient.RegistrationAccessToken = unit.GenerateRegistrationAccessToken()
	}
	setDefaults(ctx, dynamicClient)
}

func newClient(dynamicClient models.DynamicClientRequest) models.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.RegistrationAccessToken), bcrypt.DefaultCost)
	client := models.Client{
		Id:                            dynamicClient.Id,
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                dynamicClient.ClientMetaInfo,
	}

	if dynamicClient.AuthnMethod == constants.ClientSecretPostAuthn || dynamicClient.AuthnMethod == constants.ClientSecretBasicAuthn {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.Secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == constants.ClientSecretJwt {
		client.Secret = dynamicClient.Secret
	}

	return client
}

func getClientRegistrationUri(ctx utils.Context, clientId string) string {
	return ctx.Host + string(constants.DynamicClientEndpoint) + "/" + clientId
}

func getProtectedClient(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) (
	models.Client,
	models.OAuthError,
) {
	if dynamicClient.Id == "" {
		return models.Client{}, models.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(dynamicClient.Id)
	if err != nil {
		return models.Client{}, models.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return models.Client{}, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return client, nil
}
