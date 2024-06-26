package dcr

import (
	"fmt"
	"slices"

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
		validateClientSignatureAlgorithmForPrivateKeyJWT,
		validateClientSignatureAlgorithmForClientSecretJWT,
		validateJWKSAreRequiredForPrivateKeyJWTAuthn,
		validateJWKSIsRequiredWhenSelfSignedTLSAuthn,
		validateTLSSubjectInfoWhenTLSAuthn,
		validateGrantTypes,
		validateClientCredentialsGrantNotAllowedForNoneClientAuthn,
		validateClientAuthnMethodForIntrospectionGrant,
		validateRedirectURIS,
		validateResponseTypes,
		validateCannotRequestImplicitResponseTypeWithoutImplicitGrant,
		validateScopes,
		validateOpenIDScopeIfRequired,
		validateSubjectIDentifierType,
		validateIDTokenSignatureAlgorithm,
		validateIDTokenEncryptionAlgorithms,
		validateUserInfoSignatureAlgorithm,
		validateUserInfoEncryptionAlgorithms,
		validateJARSignatureAlgorithm,
		validateJAREncryptionAlgorithms,
		validateJARMSignatureAlgorithm,
		validateJARMEncryptionAlgorithms,
		validatePublicJWKS,
		validatePublicJWKSURI,
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

func validateRedirectURIS(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if len(dynamicClient.RedirectURIS) == 0 {
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

func validateOpenIDScopeIfRequired(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.Scopes != "" && ctx.OpenIDScopeIsRequired && utils.ScopesContainsOpenID(dynamicClient.Scopes) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "scope openid is required")
	}
	return nil
}

func validateSubjectIDentifierType(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.SubjectIDentifierType != "" && !goidc.ContainsAll(ctx.SubjectIDentifierTypes, dynamicClient.SubjectIDentifierType) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "subject_type not supported")
	}
	return nil
}

func validateIDTokenSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.IDTokenSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.GetUserInfoSignatureAlgorithms(), dynamicClient.IDTokenSignatureAlgorithm) {
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

func validateJARSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.JARSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.JARSignatureAlgorithms, dynamicClient.JARSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSignatureAlgorithm(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.JARMSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.GetJARMSignatureAlgorithms(), dynamicClient.JARMSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJWT(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.PrivateKeyJWTAuthn {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.PrivateKeyJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJWT(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.ClientSecretJWT {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm != "" && !goidc.ContainsAll(ctx.ClientSecretJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJWKSAreRequiredForPrivateKeyJWTAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.PrivateKeyJWTAuthn {
		return nil
	}

	if len(dynamicClient.PublicJWKS.Keys) == 0 && dynamicClient.PublicJWKSURI == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJWKSIsRequiredWhenSelfSignedTLSAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.SelfSignedTLSAuthn {
		return nil
	}

	if dynamicClient.PublicJWKSURI == "" && len(dynamicClient.PublicJWKS.Keys) == 0 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSSubjectInfoWhenTLSAuthn(
	_ utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.AuthnMethod != goidc.TLSAuthn {
		return nil
	}

	numberOfIDentifiers := 0

	if dynamicClient.TLSSubjectDistinguishedName != "" {
		numberOfIDentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeName != "" {
		numberOfIDentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeNameIp != "" {
		numberOfIDentifiers++
	}

	if numberOfIDentifiers != 1 {
		return goidc.NewOAuthError(goidc.InvalidRequest, "only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if ID token encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" || dynamicClient.IDTokenContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "ID token encryption is not supported")
		}
		return nil
	}

	if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.IDTokenKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_encrypted_response_alg not supported")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && dynamicClient.IDTokenKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.IDTokenContentEncryptionAlgorithm) {
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

func validateJARMEncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARMIsEnabled {
		if dynamicClient.JARMKeyEncryptionAlgorithm != "" || dynamicClient.JARMContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "jarm encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARMKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMKeyEncrytionAlgorithms, dynamicClient.JARMKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_alg not supported")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && dynamicClient.JARMKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMContentEncryptionAlgorithms, dynamicClient.JARMContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncryptionAlgorithms(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAREncryptionIsEnabled {
		if dynamicClient.JARKeyEncryptionAlgorithm != "" || dynamicClient.JARContentEncryptionAlgorithm != "" {
			return goidc.NewOAuthError(goidc.InvalidRequest, "jar encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.GetJARKeyEncryptionAlgorithms(), dynamicClient.JARKeyEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_alg not supported")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && dynamicClient.JARKeyEncryptionAlgorithm == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARContentEncryptionAlgorithms, dynamicClient.JARContentEncryptionAlgorithm) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx utils.Context,
	dynamicClient goidc.DynamicClient,
) goidc.OAuthError {
	if dynamicClient.PublicJWKS == nil {
		return nil
	}

	for _, jwk := range dynamicClient.PublicJWKS.Keys {
		if !jwk.IsPublic() || !jwk.IsValid() {
			return goidc.NewOAuthError(goidc.InvalidRequest, fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.GetKeyID()))
		}
	}
	return nil
}

func validatePublicJWKSURI(
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
