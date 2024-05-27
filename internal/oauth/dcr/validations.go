package dcr

import (
	"slices"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateDynamicClientRequest(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	return runValidations(
		ctx, dynamicClient,
		validateAuthnMethod,
		validateClientSignatureAlgorithms,
		validateGrantTypes,
		validateRedirectUris,
		validateResponseTypes,
		validateCannotRequestImplicitResponseTypeWithoutImplicitGrant,
		validateScopes,
		validateOpenIdScopeIfRequired,
		validateSubjectIdentifierType,
		validateIdTokenSignatureAlgorithm,
		validateJarSignatureAlgorithm,
		validateJarmSignatureAlgorithm,
	)
}

func runValidations(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
	validations ...func(
		ctx utils.Context,
		dynamicClient models.DynamicClientRequest,
	) models.OAuthError,
) models.OAuthError {
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
) models.OAuthError {
	if !unit.ContainsAll(ctx.GrantTypes, dynamicClient.GrantTypes...) {
		return models.NewOAuthError(constants.InvalidRequest, "grant type not allowed")
	}
	return nil
}

func validateRedirectUris(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if len(dynamicClient.RedirectUris) == 0 {
		return models.NewOAuthError(constants.InvalidRequest, "at least one redirect uri must be informed")
	}
	return nil
}

func validateResponseTypes(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if !unit.ContainsAll(ctx.ResponseTypes, dynamicClient.ResponseTypes...) {
		return models.NewOAuthError(constants.InvalidRequest, "response type not allowed")
	}
	return nil
}

func validateCannotRequestImplicitResponseTypeWithoutImplicitGrant(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	containsImplicitResponseType := false
	for _, rt := range dynamicClient.ResponseTypes {
		if rt.IsImplicit() {
			containsImplicitResponseType = true
		}
	}

	if containsImplicitResponseType && !slices.Contains(ctx.GrantTypes, constants.ImplicitGrant) {
		return models.NewOAuthError(constants.InvalidRequest, "implicit grant type is required for implicit response types")
	}
	return nil
}

func validateAuthnMethod(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if !unit.ContainsAll(ctx.ClientAuthnMethods, dynamicClient.AuthnMethod) {
		return models.NewOAuthError(constants.InvalidRequest, "authn method not allowed")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.Scopes != "" && !unit.ContainsAll(ctx.Scopes, unit.SplitStringWithSpaces(dynamicClient.Scopes)...) {
		return models.NewOAuthError(constants.InvalidRequest, "scope not allowed")
	}
	return nil
}

func validateOpenIdScopeIfRequired(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.Scopes != "" && ctx.OpenIdScopeIsRequired && unit.ScopesContainsOpenId(dynamicClient.Scopes) {
		return models.NewOAuthError(constants.InvalidRequest, "scope openid is required")
	}
	return nil
}

func validateSubjectIdentifierType(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.SubjectIdentifierType != "" && !unit.ContainsAll(ctx.SubjectIdentifierTypes, dynamicClient.SubjectIdentifierType) {
		return models.NewOAuthError(constants.InvalidRequest, "subject_type not supported")
	}
	return nil
}

func validateIdTokenSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.IdTokenSignatureAlgorithm != "" && !unit.ContainsAll(ctx.GetIdTokenSignatureAlgorithms(), dynamicClient.IdTokenSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJarSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.JarSignatureAlgorithm != "" && !unit.ContainsAll(ctx.JarSignatureAlgorithms, dynamicClient.JarSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "request_object_signing_alg not supported")
	}
	return nil
}

func validateJarmSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.JarmSignatureAlgorithm != "" && !unit.ContainsAll(ctx.GetJarmSignatureAlgorithms(), dynamicClient.JarmSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithms(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	//TODO: It depends if it is private_key_jwt or client_secret_jwt.
	if dynamicClient.AuthnSignatureAlgorithm != "" && !unit.ContainsAll(ctx.ClientSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}
