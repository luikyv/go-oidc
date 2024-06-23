package dcr

import (
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func setDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientSecretBasicAuthn
	}

	if dynamicClient.AuthnMethod == goidc.ClientSecretPostAuthn ||
		dynamicClient.AuthnMethod == goidc.ClientSecretBasicAuthn ||
		dynamicClient.AuthnMethod == goidc.ClientSecretJwt {
		dynamicClient.Secret = unit.GenerateClientSecret()
	}

	if dynamicClient.Scopes == "" {
		dynamicClient.Scopes = strings.Join(ctx.Scopes, " ")
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []goidc.ResponseType{goidc.CodeResponse}
	}

	if ctx.PkceIsEnabled && dynamicClient.AuthnMethod == goidc.NoneAuthn {
		dynamicClient.PkceIsRequired = true
	}

	if dynamicClient.IdTokenKeyEncryptionAlgorithm != "" && dynamicClient.IdTokenContentEncryptionAlgorithm == "" {
		dynamicClient.IdTokenContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && dynamicClient.UserInfoContentEncryptionAlgorithm == "" {
		dynamicClient.UserInfoContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.JarmKeyEncryptionAlgorithm != "" && dynamicClient.JarmContentEncryptionAlgorithm == "" {
		dynamicClient.JarmContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.JarKeyEncryptionAlgorithm != "" && dynamicClient.JarContentEncryptionAlgorithm == "" {
		dynamicClient.JarContentEncryptionAlgorithm = jose.A128CBC_HS256
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

	if dynamicClient.AuthnMethod == goidc.ClientSecretPostAuthn || dynamicClient.AuthnMethod == goidc.ClientSecretBasicAuthn {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.Secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == goidc.ClientSecretJwt {
		client.Secret = dynamicClient.Secret
	}

	return client
}

func getClientRegistrationUri(ctx utils.Context, clientId string) string {
	return ctx.Host + string(goidc.DynamicClientEndpoint) + "/" + clientId
}

func getProtectedClient(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) (
	models.Client,
	models.OAuthError,
) {
	if dynamicClient.Id == "" {
		return models.Client{}, models.NewOAuthError(goidc.InvalidRequest, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(dynamicClient.Id)
	if err != nil {
		return models.Client{}, models.NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return models.Client{}, models.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	return client, nil
}
