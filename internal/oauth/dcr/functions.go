package dcr

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func setDefaults(_ utils.Context, dynamicClient *utils.DynamicClientRequest) {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientSecretBasicAuthn
	}

	if dynamicClient.AuthnMethod == goidc.ClientSecretPostAuthn ||
		dynamicClient.AuthnMethod == goidc.ClientSecretBasicAuthn ||
		dynamicClient.AuthnMethod == goidc.ClientSecretJWT {
		dynamicClient.Secret = utils.GenerateClientSecret()
	}

	if dynamicClient.Scopes == "" {
		dynamicClient.Scopes = goidc.OpenIDScope
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []goidc.ResponseType{goidc.CodeResponse}
	}

	if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" && dynamicClient.IDTokenContentEncryptionAlgorithm == "" {
		dynamicClient.IDTokenContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && dynamicClient.UserInfoContentEncryptionAlgorithm == "" {
		dynamicClient.UserInfoContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.JARMKeyEncryptionAlgorithm != "" && dynamicClient.JARMContentEncryptionAlgorithm == "" {
		dynamicClient.JARMContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.JARKeyEncryptionAlgorithm != "" && dynamicClient.JARContentEncryptionAlgorithm == "" {
		dynamicClient.JARContentEncryptionAlgorithm = jose.A128CBC_HS256
	}

	if dynamicClient.Attributes == nil {
		dynamicClient.Attributes = make(map[string]any)
	}
}

func setCreationDefaults(ctx utils.Context, dynamicClient *utils.DynamicClientRequest) {
	dynamicClient.ID = utils.GenerateClientID()
	dynamicClient.RegistrationAccessToken = utils.GenerateRegistrationAccessToken()
	setDefaults(ctx, dynamicClient)
}

func setUpdateDefaults(
	ctx utils.Context,
	client goidc.Client,
	dynamicClient *utils.DynamicClientRequest,
) {
	dynamicClient.ID = client.ID
	if ctx.ShouldRotateRegistrationTokens {
		dynamicClient.RegistrationAccessToken = utils.GenerateRegistrationAccessToken()
	}
	setDefaults(ctx, dynamicClient)
}

func newClient(dynamicClient utils.DynamicClientRequest) goidc.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.RegistrationAccessToken), bcrypt.DefaultCost)
	client := goidc.Client{
		ID:                            dynamicClient.ID,
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                dynamicClient.ClientMetaInfo,
	}

	if dynamicClient.AuthnMethod == goidc.ClientSecretPostAuthn || dynamicClient.AuthnMethod == goidc.ClientSecretBasicAuthn {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.Secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == goidc.ClientSecretJWT {
		client.Secret = dynamicClient.Secret
	}

	return client
}

func getClientRegistrationURI(ctx utils.Context, clientID string) string {
	return ctx.Host + string(goidc.DynamicClientEndpoint) + "/" + clientID
}

func getProtectedClient(
	ctx utils.Context,
	dynamicClient utils.DynamicClientRequest,
) (
	goidc.Client,
	goidc.OAuthError,
) {
	if dynamicClient.ID == "" {
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidRequest, "invalid client_id")
	}

	client, err := ctx.GetClient(dynamicClient.ID)
	if err != nil {
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return goidc.Client{}, goidc.NewOAuthError(goidc.AccessDenied, "invalid token")
	}

	return client, nil
}
