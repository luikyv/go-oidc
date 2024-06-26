package dcr

import (
	"fmt"
	"slices"

	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateDynamicClientRequest(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	return runValidations(
		ctx, dynamicClient,
		validateAuthnMethod,
		validateClientSignatureAlgorithmForPrivateKeyJwt,
		validateClientSignatureAlgorithmForClientSecretJwt,
		validateJwksAreRequiredForPrivateKeyJwtAuthn,
		validateJwksIsRequiredWhenSelfSignedTlsAuthn,
		validateTlsSubjectInfoWhenTlsAuthn,
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
		validateIdTokenEncryptionAlgorithms,
		validateUserInfoSignatureAlgorithm,
		validateUserInfoEncryptionAlgorithms,
		validateJarSignatureAlgorithm,
		validateJarEncryptionAlgorithms,
		validateJarmSignatureAlgorithm,
		validateJarmEncryptionAlgorithms,
		validatePublicJwks,
		validatePublicJwksUri,
		validateAuthorizationDetailTypes,
	)
}

func runValidations(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
	validations ...func(
		ctx utils.Context,
		dynamicClient goidc.DynamicClient,
	) goidc.OAuthError,
) goidc.OAuthError {
	for _, validation := range validations {
		if err := validation(ctx, dynamicClient); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.GrantTypes, dynamicClient.GrantTypes...) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "grant type not allowed")
	}
	return nil
}

func validateClientCredentialsGrantNotAllowedForNoneClientAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.NoneAuthn {
		return nil
	}

	if slices.Contains(dynamicClient.GrantTypes, goidc.ClientCredentialsGrant) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateClientAuthnMethodForIntrospectionGrant(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if slices.Contains(dynamicClient.GrantTypes, goidc.IntrospectionGrant) &&
		!slices.Contains(ctx.IntrospectionClientAuthnMethods, dynamicClient.AuthnMethod) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateRedirectUris(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if len(dynamicClient.RedirectUris) == 0 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "at least one redirect uri must be informed")
	}
	return nil
}

func validateResponseTypes(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.ResponseTypes, dynamicClient.ResponseTypes...) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "response type not allowed")
	}
	return nil
}

func validateCannotRequestImplicitResponseTypeWithoutImplicitGrant(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	containsImplicitResponseType := false
	for _, rt := range dynamicClient.ResponseTypes {
		if rt.IsImplicit() {
			containsImplicitResponseType = true
		}
	}

	if containsImplicitResponseType && !slices.Contains(ctx.GrantTypes, goidc.ImplicitGrant) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "implicit grant type is required for implicit response types")
	}
	return nil
}

func validateAuthnMethod(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if !goidc.ContainsAll(ctx.ClientAuthnMethods, dynamicClient.AuthnMethod) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authn method not allowed")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.Scopes != "" && !goidc.ContainsAll(ctx.Scopes, goidc.SplitStringWithSpaces(dynamicClient.Scopes)...) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "scope not allowed")
	}
	return nil
}

func validateOpenIdScopeIfRequired(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.Scopes != "" && ctx.OpenIdScopeIsRequired && unit.ScopesContainsOpenId(dynamicClient.Scopes) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "scope openid is required")
	}
	return nil
}

func validateSubjectIdentifierType(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.SubjectIdentifierType != "" && !goidc.ContainsAll(ctx.SubjectIdentifierTypes, dynamicClient.SubjectIdentifierType) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "subject_type not supported")
	}
	return nil
}

func validateIdTokenSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.IdTokenSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.GetUserInfoSignatureAlgorithms(), dynamicClient.IdTokenSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.UserInfoSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.GetUserInfoSignatureAlgorithms(), dynamicClient.UserInfoSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJarSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.JarSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.JarSignatureAlgorithms, dynamicClient.JarSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_signing_alg not supported")
	}
	return nil
}

func validateJarmSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.JarmSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.GetJarmSignatureAlgorithms(), dynamicClient.JarmSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJwt(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.PrivateKeyJwtAuthn {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.PrivateKeyJwtSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJwt(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientSecretJwt {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.ClientSecretJwtSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJwksAreRequiredForPrivateKeyJwtAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.PrivateKeyJwtAuthn {
		return nil
	}

	if len(dynamicClient.PublicJwks.Keys) == 0 && dynamicClient.PublicJwksUri == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJwksIsRequiredWhenSelfSignedTlsAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.SelfSignedTlsAuthn {
		return nil
	}

	if dynamicClient.PublicJwksUri == "" && len(dynamicClient.PublicJwks.Keys) == 0 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTlsSubjectInfoWhenTlsAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.TlsAuthn {
		return nil
	}

	numberOfIdentifiers := 0

	if dynamicClient.TlsSubjectDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TlsSubjectAlternativeName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TlsSubjectAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIdTokenEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if ID token encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.IdTokenKeyEncryptionAlgorithm != "" || dynamicClient.IdTokenContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "ID token encryption is not supported")
		}
		return nil
	}

	if dynamicClient.IdTokenKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.IdTokenKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_encrypted_response_alg not supported")
	}

	if dynamicClient.IdTokenContentEncryptionAlgorithm != "" && dynamicClient.IdTokenKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dynamicClient.IdTokenContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.IdTokenContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if user info encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" || dynamicClient.UserInfoContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "user info encryption is not supported")
		}
		return nil
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.UserInfoKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "userinfo_encrypted_response_alg not supported")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && dynamicClient.UserInfoKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.UserInfoContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJarmEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JarmIsEnabled {
		if dynamicClient.JarmKeyEncryptionAlgorithm != "" || dynamicClient.JarmContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "jarm encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JarmKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JarmKeyEncrytionAlgorithms, dynamicClient.JarmKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_alg not supported")
	}

	if dynamicClient.JarmContentEncryptionAlgorithm != "" && dynamicClient.JarmKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dynamicClient.JarmContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JarmContentEncryptionAlgorithms, dynamicClient.JarmContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJarEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JarEncryptionIsEnabled {
		if dynamicClient.JarKeyEncryptionAlgorithm != "" || dynamicClient.JarContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "jar encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JarKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.GetJarKeyEncryptionAlgorithms(), dynamicClient.JarKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_alg not supported")
	}

	if dynamicClient.JarContentEncryptionAlgorithm != "" && dynamicClient.JarKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dynamicClient.JarContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JarContentEncryptionAlgorithms, dynamicClient.JarContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJwks(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.PublicJwks == nil {
		return nil
	}

	for _, jwk := range dynamicClient.PublicJwks.Keys {
		if !jwk.IsPublic() || !jwk.IsValid() {
			return goidc.NewOAuthError(goidc.InvalidRequest, fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.GetKeyId()))
		}
	}
	return nil
}

func validatePublicJwksUri(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if !ctx.AuthorizationDetailsParameterIsEnabled || dynamicClient.AuthorizationDetailTypes == nil {
		return nil
	}

	if goidc.ContainsAll(ctx.AuthorizationDetailTypes, dynamicClient.AuthorizationDetailTypes...) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization detail type not supported")
	}

	return nil
}
