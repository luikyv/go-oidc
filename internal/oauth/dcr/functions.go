package dcr

import (
	"strings"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func setCreationDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	dynamicClient.Id = unit.GenerateClientId()
	dynamicClient.RegistrationAccessToken = unit.GenerateRegistrationAccessToken() // TODO: Implement flag to rotate access token.
	if dynamicClient.AuthnMethod == constants.ClientSecretPostAuthn || dynamicClient.AuthnMethod == constants.ClientSecretBasicAuthn {
		dynamicClient.Secret = unit.GenerateClientSecret()
	}

	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = constants.ClientSecretBasicAuthn
	}

	if dynamicClient.Scopes == "" {
		dynamicClient.Scopes = strings.Join(ctx.Scopes, " ")
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []constants.ResponseType{constants.CodeResponse}
	}
}

func setUpdateDefaults(ctx utils.Context, client models.Client, dynamicClient *models.DynamicClientRequest) {
	setCreationDefaults(ctx, dynamicClient)
	dynamicClient.Id = client.Id
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

func getProtectedClient(ctx utils.Context, clientId string, token string) (models.Client, models.OAuthError) {
	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		return models.Client{}, models.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if !client.IsRegistrationAccessTokenValid(token) {
		return models.Client{}, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return client, nil
}
