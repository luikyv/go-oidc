package oauth

import (
	"slices"

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
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return models.DynamicClientResponse{}, err
	}

	setDynamicClientDefaults(ctx, &dynamicClient)

	client, resp := NewClient(dynamicClient.ClientMetaInfo)
	if err := ctx.ClientManager.Create(client); err != nil {
		return models.DynamicClientResponse{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	return resp, nil
}

func setDynamicClientDefaults(ctx utils.Context, dynamicClient *models.DynamicClientRequest) {
	dynamicClient.PkceIsRequired = ctx.PkceIsRequired
}

func NewClient(meta models.ClientMetaInfo) (models.Client, models.DynamicClientResponse) {
	registrationAccessToken := unit.GenerateRegistrationAccessToken()
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(registrationAccessToken), 0)
	client := models.Client{
		Id:                            unit.GenerateDynamicClientId(),
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo:                meta,
	}
	resp := models.DynamicClientResponse{
		Id:                      client.Id,
		RegistrationAccessToken: registrationAccessToken,
		ClientMetaInfo:          meta,
	}

	if meta.AuthnMethod == constants.ClientSecretPostAuthn || meta.AuthnMethod == constants.ClientSecretBasicAuthn {
		secret := unit.GenerateClientSecret()
		resp.Secret = secret
		client.SecretSalt = "random_salt" // TODO
		clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(client.SecretSalt+secret), 0)
		client.HashedSecret = string(clientHashedSecret)

	}

	if meta.AuthnMethod == constants.ClientSecretJwt {
		client.Secret = unit.GenerateClientSecret()
	}

	return client, resp
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

	if containsImplictResponseType && !slices.Contains(ctx.GrantTypes, constants.ImplictGrant) {
		return issues.NewOAuthError(constants.InvalidRequest, "implict grant type is required for implict response types")
	}
	return nil
}
