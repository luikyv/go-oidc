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
		validateClientSignatureAlgorithmForPrivateKeyJwt,
		validateClientSignatureAlgorithmForClientSecretJwt,
		validateJwksAreRequiredForPrivateKeyJwtAuthn,
		validateJwksIsRequiredWhenSelfSignedTlsAuthn,
		validateGrantTypes,
		validateClientCredentialsGrantNotAllowedForNoneClientAuthn,
		validateClientAuthnMethodForIntrospectionGrant,
		validateRedirectUris,
		validateResponseTypes,
		validateCannotRequestImplicitResponseTypeWithoutImplicitGrant,
		validateScopes,
		validateOpenIdScopeIfRequired,
		validateSubjectIdentifierType,
		validateIdTokenSignatureAlgorithm,
		validateJarSignatureAlgorithm,
		validateJarmSignatureAlgorithm,
		validatePkceIsRequiredForPublicClients,
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

func validateClientCredentialsGrantNotAllowedForNoneClientAuthn(
	_ utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.AuthnMethod != constants.NoneAuthn {
		return nil
	}

	if slices.Contains(dynamicClient.GrantTypes, constants.ClientCredentialsGrant) {
		return models.NewOAuthError(constants.InvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateClientAuthnMethodForIntrospectionGrant(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if slices.Contains(dynamicClient.GrantTypes, constants.IntrospectionGrant) &&
		!slices.Contains(ctx.IntrospectionClientAuthnMethods, dynamicClient.AuthnMethod) {
		return models.NewOAuthError(constants.InvalidRequest, "client_credentials grant type not allowed")
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

func validateClientSignatureAlgorithmForPrivateKeyJwt(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.AuthnMethod != constants.PrivateKeyJwtAuthn {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !unit.ContainsAll(ctx.PrivateKeyJwtSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJwt(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.AuthnMethod != constants.ClientSecretJwt {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !unit.ContainsAll(ctx.ClientSecretJwtSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return models.NewOAuthError(constants.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJwksAreRequiredForPrivateKeyJwtAuthn(
	_ utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.AuthnMethod != constants.PrivateKeyJwtAuthn {
		return nil
	}

	if len(dynamicClient.PublicJwks.Keys) == 0 && dynamicClient.PublicJwksUri == "" {
		return models.NewOAuthError(constants.InvalidRequest, "the jwks is required for private_key_jwt")
	}

	return nil
}

func validatePkceIsRequiredForPublicClients(
	ctx utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if ctx.PkceIsEnabled && dynamicClient.AuthnMethod == constants.NoneAuthn && !dynamicClient.PkceIsRequired {
		return models.NewOAuthError(constants.InvalidRequest, "pkce is required for public clients")
	}
	return nil
}

func validateJwksIsRequiredWhenSelfSignedTlsAuthn(
	_ utils.Context,
	dynamicClient models.DynamicClientRequest,
) models.OAuthError {
	if dynamicClient.AuthnMethod != constants.SelfSignedTlsAuthn {
		return nil
	}

	if dynamicClient.PublicJwksUri == "" && len(dynamicClient.PublicJwks.Keys) == 0 {
		return models.NewOAuthError(constants.InvalidRequest, "jwks is required when authenticating with self signed certificates")
	}

	return nil
}
