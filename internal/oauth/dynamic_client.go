package oauth

import (
	"slices"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func RegisterClient(ctx utils.Context, dynamicClient models.DynamicClientRequest) issues.OAuthError {
	if err := validateDynamicClientRequest(ctx, dynamicClient); err != nil {
		return err
	}

	client := convertDynamicClientToClient(ctx, dynamicClient)
	if err := ctx.ClientManager.Create(client); err != nil {
		return issues.NewOAuthError(constants.InternalError, err.Error())
	}
	return nil
}

func convertDynamicClientToClient(ctx utils.Context, dynamicClient models.DynamicClientRequest) models.Client {
	client := models.Client{}
	setClientDefaults(ctx, &client)
	return client
}

func setClientDefaults(ctx utils.Context, client *models.Client) {

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
