package client

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TODO: Clear this.
func validateDynamicClientRequest(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	return runValidations(
		ctx, dynamicClient,
		validateAuthnMethod,
		validateScopes,
		validateClientSignatureAlgorithmForPrivateKeyJWT,
		validateClientSignatureAlgorithmForClientSecretJWT,
		validateJWKSAreRequiredForPrivateKeyJWTAuthn,
		validateJWKSIsRequiredWhenSelfSignedTLSAuthn,
		validateTLSSubjectInfoWhenTLSAuthn,
		validateGrantTypes,
		validateRefreshTokenGrant,
		validateRedirectURIS,
		validateResponseTypes,
		validateOpenIDScopeIfRequired,
		validateSubjectIdentifierType,
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
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
	validations ...func(
		ctx *oidc.Context,
		dynamicClient dynamicClientRequest,
	) oidc.Error,
) oidc.Error {
	for _, validation := range validations {
		if err := validation(ctx, dynamicClient); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	for _, gt := range dynamicClient.GrantTypes {
		if !slices.Contains(ctx.GrantTypes, gt) {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "grant type not allowed")
		}
	}

	if dynamicClient.AuthnMethod == goidc.ClientAuthnNone &&
		slices.Contains(dynamicClient.GrantTypes, goidc.GrantClientCredentials) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "client_credentials grant type not allowed")
	}

	if slices.Contains(dynamicClient.GrantTypes, goidc.GrantIntrospection) &&
		!slices.Contains(ctx.IntrospectionClientAuthnMethods, dynamicClient.AuthnMethod) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "client_credentials grant type not allowed")
	}

	return nil
}

func validateRedirectURIS(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if len(dynamicClient.RedirectURIS) == 0 {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "at least one redirect uri must be informed")
	}
	return nil
}

func validateResponseTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {

	for _, rt := range dynamicClient.ResponseTypes {
		if !slices.Contains(ctx.ResponseTypes, rt) {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "response type not allowed")
		}
	}

	if !slices.Contains(ctx.GrantTypes, goidc.GrantImplicit) {
		for _, rt := range dynamicClient.ResponseTypes {
			if rt.IsImplicit() {
				return oidc.NewError(oidc.ErrorCodeInvalidRequest, "implicit grant type is required for implicit response types")
			}
		}
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "implicit grant type is required for implicit response types")
	}

	return nil
}

func validateAuthnMethod(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if !slices.Contains(ctx.ClientAuthnMethods, dynamicClient.AuthnMethod) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authn method not allowed")
	}
	return nil
}

func validateOpenIDScopeIfRequired(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if !ctx.OpenIDScopeIsRequired {
		return nil
	}

	if dynamicClient.Scopes != "" || !strutil.ContainsOpenID(dynamicClient.Scopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "scope openid is required")
	}

	return nil
}

func validateSubjectIdentifierType(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.SubjectIdentifierType == "" {
		return nil
	}

	if !slices.Contains(ctx.SubjectIdentifierTypes, dynamicClient.SubjectIdentifierType) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "subject_type not supported")
	}
	return nil
}

func validateIDTokenSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.IDTokenSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dynamicClient.IDTokenSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.UserInfoSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dynamicClient.UserInfoSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.JARSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.JARSignatureAlgorithms, dynamicClient.JARSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSignatureAlgorithm(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.JARMSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.JARMSignatureAlgorithms(), dynamicClient.JARMSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJWT(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.PrivateKeyJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJWT(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnSecretJWT {
		return nil
	}

	if dynamicClient.AuthnSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.ClientSecretJWTSignatureAlgorithms, dynamicClient.AuthnSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJWKSAreRequiredForPrivateKeyJWTAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dynamicClient.PublicJWKS == nil && dynamicClient.PublicJWKSURI == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJWKSIsRequiredWhenSelfSignedTLSAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnSelfSignedTLS {
		return nil
	}

	if dynamicClient.PublicJWKSURI == "" && dynamicClient.PublicJWKS == nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSSubjectInfoWhenTLSAuthn(
	_ *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.AuthnMethod != goidc.ClientAuthnTLS {
		return nil
	}

	numberOfIdentifiers := 0

	if dynamicClient.TLSSubjectDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeName != "" {
		numberOfIdentifiers++
	}

	if dynamicClient.TLSSubjectAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	// Return an error if ID token encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" || dynamicClient.IDTokenContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "ID token encryption is not supported")
		}
		return nil
	}

	if dynamicClient.IDTokenKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.IDTokenKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_alg not supported")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && dynamicClient.IDTokenKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dynamicClient.IDTokenContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.IDTokenContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	// Return an error if user info encryption is not enabled, but the client requested it.
	if !ctx.UserInfoEncryptionIsEnabled {
		if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" || dynamicClient.UserInfoContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "user info encryption is not supported")
		}
		return nil
	}

	if dynamicClient.UserInfoKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoKeyEncryptionAlgorithms, dynamicClient.UserInfoKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_alg not supported")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && dynamicClient.UserInfoKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dynamicClient.UserInfoContentEncryptionAlgorithm != "" && !slices.Contains(ctx.UserInfoContentEncryptionAlgorithms, dynamicClient.UserInfoContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARMIsEnabled {
		if dynamicClient.JARMKeyEncryptionAlgorithm != "" || dynamicClient.JARMContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "jarm encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARMKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMKeyEncrytionAlgorithms, dynamicClient.JARMKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_alg not supported")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && dynamicClient.JARMKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dynamicClient.JARMContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARMContentEncryptionAlgorithms, dynamicClient.JARMContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncryptionAlgorithms(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAREncryptionIsEnabled {
		if dynamicClient.JARKeyEncryptionAlgorithm != "" || dynamicClient.JARContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "jar encryption is not supported")
		}
		return nil
	}

	if dynamicClient.JARKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARKeyEncryptionAlgorithms(), dynamicClient.JARKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_object_encryption_alg not supported")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && dynamicClient.JARKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dynamicClient.JARContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARContentEncryptionAlgorithms, dynamicClient.JARContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if dynamicClient.PublicJWKS == nil {
		return nil
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(dynamicClient.PublicJWKS, &jwks); err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid jwks")
	}

	for _, jwk := range jwks.Keys {
		if !jwk.IsPublic() || !jwk.Valid() {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.KeyID))
		}
	}
	return nil
}

func validatePublicJWKSURI(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if !ctx.AuthorizationDetailsParameterIsEnabled || dynamicClient.AuthorizationDetailTypes == nil {
		return nil
	}

	for _, dt := range dynamicClient.AuthorizationDetailTypes {
		if !slices.Contains(ctx.AuthorizationDetailTypes, dt) {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "authorization detail type not supported")
		}
	}

	return nil
}

func validateRefreshTokenGrant(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	if strutil.ContainsOfflineAccess(dynamicClient.Scopes) && !slices.Contains(dynamicClient.GrantTypes, goidc.GrantRefreshToken) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "refresh_token grant is required for using the scope offline_access")
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	dynamicClient dynamicClientRequest,
) oidc.Error {
	for _, requestedScope := range strutil.SplitWithSpaces(dynamicClient.Scopes) {
		matches := false
		for _, scope := range ctx.Scopes {
			if requestedScope == scope.ID {
				matches = true
				break
			}
		}
		if !matches {
			return oidc.NewError(oidc.ErrorCodeInvalidRequest, "scope "+requestedScope+" is not valid")
		}
	}

	return nil
}
