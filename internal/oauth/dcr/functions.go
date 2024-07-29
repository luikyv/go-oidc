package dcr

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func setDefaults(ctx *utils.Context, dynamicClient *utils.DynamicClientRequest) goidc.OAuthError {
	if dynamicClient.AuthnMethod == "" {
		dynamicClient.AuthnMethod = goidc.ClientAuthnSecretBasic
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnSecretPost ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretBasic ||
		dynamicClient.AuthnMethod == goidc.ClientAuthnSecretJWT {
		secret, err := utils.ClientSecret()
		if err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		dynamicClient.Secret = secret
	}

	if dynamicClient.Scopes != "" {
		scopeIDs := goidc.SplitStringWithSpaces(dynamicClient.Scopes)
		dynamicClient.Scopes = ctx.Scopes.SubSet(scopeIDs).String()
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

	if dynamicClient.CustomAttributes == nil {
		dynamicClient.CustomAttributes = make(map[string]any)
	}

	return nil
}

func setCreationDefaults(
	ctx *utils.Context,
	dynamicClient *utils.DynamicClientRequest,
) goidc.OAuthError {
	id, err := utils.ClientID()
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	dynamicClient.ID = id

	token, err := utils.RegistrationAccessToken()
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	dynamicClient.RegistrationAccessToken = token

	return setDefaults(ctx, dynamicClient)
}

func setUpdateDefaults(
	ctx *utils.Context,
	client *goidc.Client,
	dynamicClient *utils.DynamicClientRequest,
) goidc.OAuthError {
	dynamicClient.ID = client.ID
	if ctx.ShouldRotateRegistrationTokens {
		token, err := utils.RegistrationAccessToken()
		if err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		dynamicClient.RegistrationAccessToken = token
	}

	return setDefaults(ctx, dynamicClient)
}

func newClient(dynamicClient utils.DynamicClientRequest) *goidc.Client {
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

func getClientRegistrationURI(ctx *utils.Context, clientID string) string {
	return ctx.Host + string(goidc.EndpointDynamicClient) + "/" + clientID
}

func getProtectedClient(
	ctx *utils.Context,
	dynamicClient utils.DynamicClientRequest,
) (
	*goidc.Client,
	goidc.OAuthError,
) {
	if dynamicClient.ID == "" {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	client, err := ctx.Client(dynamicClient.ID)
	if err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, err.Error())
	}

	if dynamicClient.RegistrationAccessToken == "" ||
		!client.IsRegistrationAccessTokenValid(dynamicClient.RegistrationAccessToken) {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid token")
	}

	return client, nil
}
