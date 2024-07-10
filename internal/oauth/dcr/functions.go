package dcr

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func setDefaults(ctx utils.OAuthContext, dynamicClient *utils.DynamicClientRequest) {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientAuthnSecretBasic
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		dynamicClient.Secret = utils.ClientSecret()
	}

	if dynamicClient.Scopes != "" {
		scopeIDs := goidc.SplitStringWithSpaces(dynamicClient.Scopes)
		dynamicClient.Scopes = ctx.Scopes().SubSet(scopeIDs).String()
	}

	if dynamicClient.ResponseTypes == nil {
		dynamicClient.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
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

func setCreationDefaults(ctx utils.OAuthContext, dynamicClient *utils.DynamicClientRequest) {
	dynamicClient.ID = utils.ClientID()
	dynamicClient.RegistrationAccessToken = utils.RegistrationAccessToken()
	setDefaults(ctx, dynamicClient)
}

func setUpdateDefaults(
	ctx utils.OAuthContext,
	client goidc.Client,
	dynamicClient *utils.DynamicClientRequest,
) {
	dynamicClient.ID = client.ID
	if ctx.ShouldRotateRegistrationTokens {
		dynamicClient.RegistrationAccessToken = utils.RegistrationAccessToken()
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

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost || dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic {
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(dynamicClient.Secret), bcrypt.DefaultCost)
		client.HashedSecret = string(clientHashedSecret)
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		client.Secret = dynamicClient.Secret
	}

	return client
}

func getClientRegistrationURI(ctx utils.OAuthContext, clientID string) string {
	return ctx.Host + string(goidc.EndpointDynamicClient) + "/" + clientID
}

func getProtectedClient(
	ctx utils.OAuthContext,
	dynamicClient utils.DynamicClientRequest,
) (
	goidc.Client,
	goidc.OAuthError,
) {
	if dynamicClient.ID == "" {
		return goidc.Client{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	client, err := ctx.Client(dynamicClient.ID)
	if err != nil {
		return goidc.Client{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, err.Error())
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return goidc.Client{}, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	return client, nil
}
