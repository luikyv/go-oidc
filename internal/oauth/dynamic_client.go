package oauth

import (
	"slices"
	"strings"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func RegisterClient(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	issues.OAuthError,
) {
	setCreationDefaults(ctx, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	client := newClient(dynamicClient)
	if err := ctx.ClientManager.Create(client); err != nil {
		return models.DynamicClientResponse{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	return models.DynamicClientResponse{
		Id:                      dynamicClient.Id,
		RegistrationUri:         getClientRegistrationUri(ctx, dynamicClient.Id),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func UpdateClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
	dynamicClient models.DynamicClientRequest,
) (
	models.DynamicClientResponse,
	issues.OAuthError,
) {
	setUpdateDefaults(ctx, clientId, &dynamicClient)
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	client := newClient(dynamicClient)
	if err := ctx.ClientManager.Update(clientId, client); err != nil {
		return models.DynamicClientResponse{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	return models.DynamicClientResponse{
		Id:                      dynamicClient.Id,
		RegistrationUri:         getClientRegistrationUri(ctx, dynamicClient.Id),
		RegistrationAccessToken: dynamicClient.RegistrationAccessToken,
		Secret:                  dynamicClient.Secret,
		ClientMetaInfo:          dynamicClient.ClientMetaInfo,
	}, nil
}

func GetClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
) (
	models.DynamicClientResponse,
	issues.OAuthError,
) {

	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		return models.DynamicClientResponse{}, issues.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if !client.IsRegistrationAccessTokenValid(registrationAccessToken) {
		return models.DynamicClientResponse{}, issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return models.DynamicClientResponse{
		Id:              client.Id,
		RegistrationUri: getClientRegistrationUri(ctx, client.Id),
		ClientMetaInfo:  client.ClientMetaInfo,
	}, nil
}

func DeleteClient(
	ctx utils.Context,
	clientId string,
	registrationAccessToken string,
) issues.OAuthError {
	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if !client.IsRegistrationAccessTokenValid(registrationAccessToken) {
		return issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if err := ctx.ClientManager.Delete(clientId); err != nil {
		return issues.NewOAuthError(constants.InternalError, err.Error())
	}
	return nil
}

func setCreationDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	dynamicClient.Id = unit.GenerateClientId()
	dynamicClient.RegistrationAccessToken = unit.GenerateRegistrationAccessToken()
	if dynamicClient.AuthnMethod == constants.ClientSecretPostAuthn || dynamicClient.AuthnMethod == constants.ClientSecretBasicAuthn {
		dynamicClient.Secret = unit.GenerateClientSecret()
	}

	if dynamicClient.Scopes == "" {
		dynamicClient.Scopes = strings.Join(ctx.Scopes, " ")
	}
}

func setUpdateDefaults(ctx utils.Context, clientId string, dynamicClient *models.DynamicClientRequest) {
	setCreationDefaults(ctx, dynamicClient)
	dynamicClient.Id = clientId
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

func validateDynamicClientRequest(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) issues.OAuthError {
	return runValidations(
		ctx, dynamicClient,
		validateGrantTypes,
		validateRedirectUris,
		validateResponseTypes,
		validateCannotRequestImplictResponseTypeWithoutImplictGrant,
	)
}

func runValidations(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
	validations ...func(
		ctx utils.Context,
		dynamicClient models.DynamicClientRequest,
	) issues.OAuthError,
) issues.OAuthError {
	for _, validation := range validations {
		if err := validation(ctx, dynamicClient); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) issues.OAuthError {
	if !unit.ContainsAll(ctx.GrantTypes, dynamicClient.GrantTypes...) {
		return issues.NewOAuthError(constants.InvalidRequest, "grant type not allowed")
	}
	return nil
}

func validateRedirectUris(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) issues.OAuthError {
	if len(dynamicClient.RedirectUris) == 0 {
		return issues.NewOAuthError(constants.InvalidRequest, "at least one redirect uri must be informed")
	}
	return nil
}

func validateResponseTypes(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) issues.OAuthError {
	if !unit.ContainsAll(ctx.ResponseTypes, dynamicClient.ResponseTypes...) {
		return issues.NewOAuthError(constants.InvalidRequest, "response type not allowed")
	}
	return nil
}

func validateCannotRequestImplictResponseTypeWithoutImplictGrant(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) issues.OAuthError {
	containsImplictResponseType := false
	for _, rt := range dynamicClient.ResponseTypes {
		if rt.IsImplict() {
			containsImplictResponseType = true
		}
	}

	if containsImplictResponseType && !slices.Contains(ctx.GrantTypes, constants.ImplicitGrant) {
		return issues.NewOAuthError(constants.InvalidRequest, "implict grant type is required for implict response types")
	}
	return nil
}
