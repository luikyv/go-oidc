package client

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateDynamicRequest(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	return runValidations(
		ctx, dc,
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
	dc dynamicRequest,
	validations ...func(
		ctx *oidc.Context,
		dc dynamicRequest,
	) oidc.Error,
) oidc.Error {
	for _, validation := range validations {
		if err := validation(ctx, dc); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	for _, gt := range dc.GrantTypes {
		if !slices.Contains(ctx.GrantTypes, gt) {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"grant type not allowed")
		}
	}

	if dc.AuthnMethod == goidc.ClientAuthnNone &&
		slices.Contains(dc.GrantTypes, goidc.GrantClientCredentials) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"client_credentials grant type not allowed")
	}

	if slices.Contains(dc.GrantTypes, goidc.GrantIntrospection) &&
		!slices.Contains(ctx.Introspection.ClientAuthnMethods, dc.AuthnMethod) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"client_credentials grant type not allowed")
	}

	return nil
}

func validateRedirectURIS(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	for _, ru := range dc.RedirectURIS {
		parsedRU, err := url.Parse(ru)
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInvalidRedirectURI,
				"invalid redirect uri")
		}
		if parsedRU.Fragment != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidRedirectURI,
				"the redirect uri cannot contain a fragment")
		}
	}

	return nil
}

func validateResponseTypes(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {

	for _, rt := range dc.ResponseTypes {
		if !slices.Contains(ctx.ResponseTypes, rt) {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"response type not allowed")
		}
	}

	if !slices.Contains(ctx.GrantTypes, goidc.GrantImplicit) {
		for _, rt := range dc.ResponseTypes {
			if rt.IsImplicit() {
				return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
					"implicit grant type is required for implicit response types")
			}
		}
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"implicit grant type is required for implicit response types")
	}

	return nil
}

func validateAuthnMethod(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if !slices.Contains(ctx.ClientAuthn.Methods, dc.AuthnMethod) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"authn method not allowed")
	}
	return nil
}

func validateOpenIDScopeIfRequired(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if !ctx.OpenIDIsRequired {
		return nil
	}

	if dc.Scopes != "" || !strutil.ContainsOpenID(dc.Scopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"scope openid is required")
	}

	return nil
}

func validateSubjectIdentifierType(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.SubjectIdentifierType == "" {
		return nil
	}

	if !slices.Contains(ctx.SubjectIdentifierTypes, dc.SubjectIdentifierType) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"subject_type not supported")
	}
	return nil
}

func validateIDTokenSignatureAlgorithm(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.IDTokenSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dc.IDTokenSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSignatureAlgorithm(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.UserInfoSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dc.UserInfoSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSignatureAlgorithm(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.JARSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.JAR.SignatureAlgorithms, dc.JARSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSignatureAlgorithm(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.JARMSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.JARMSignatureAlgorithms(), dc.JARMSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJWT(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dc.AuthnSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.ClientAuthn.PrivateKeyJWTSignatureAlgorithms, dc.AuthnSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJWT(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.AuthnMethod != goidc.ClientAuthnSecretJWT {
		return nil
	}

	if dc.AuthnSignatureAlgorithm == "" {
		return nil
	}

	if !slices.Contains(ctx.ClientAuthn.ClientSecretJWTSignatureAlgorithms, dc.AuthnSignatureAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJWKSAreRequiredForPrivateKeyJWTAuthn(
	_ *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dc.PublicJWKS == nil && dc.PublicJWKSURI == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJWKSIsRequiredWhenSelfSignedTLSAuthn(
	_ *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.AuthnMethod != goidc.ClientAuthnSelfSignedTLS {
		return nil
	}

	if dc.PublicJWKSURI == "" && dc.PublicJWKS == nil {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSSubjectInfoWhenTLSAuthn(
	_ *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.AuthnMethod != goidc.ClientAuthnTLS {
		return nil
	}

	numberOfIdentifiers := 0

	if dc.TLSSubjectDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if dc.TLSSubjectAlternativeName != "" {
		numberOfIdentifiers++
	}

	if dc.TLSSubjectAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncryptionAlgorithms(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	// Return an error if ID token encryption is not enabled, but the client requested it.
	if !ctx.User.EncryptionIsEnabled {
		if dc.IDTokenKeyEncryptionAlgorithm != "" || dc.IDTokenContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"ID token encryption is not supported")
		}
		return nil
	}

	if dc.IDTokenKeyEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.User.KeyEncryptionAlgorithms, dc.IDTokenKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg not supported")
	}

	if dc.IDTokenContentEncryptionAlgorithm != "" && dc.IDTokenKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dc.IDTokenContentEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.User.ContentEncryptionAlgorithms, dc.IDTokenContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncryptionAlgorithms(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	// Return an error if user info encryption is not enabled, but the client requested it.
	if !ctx.User.EncryptionIsEnabled {
		if dc.UserInfoKeyEncryptionAlgorithm != "" || dc.UserInfoContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"user info encryption is not supported")
		}
		return nil
	}

	if dc.UserInfoKeyEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.User.KeyEncryptionAlgorithms, dc.UserInfoKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg not supported")
	}

	if dc.UserInfoContentEncryptionAlgorithm != "" && dc.UserInfoKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dc.UserInfoContentEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.User.ContentEncryptionAlgorithms, dc.UserInfoContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncryptionAlgorithms(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARM.IsEnabled {
		if dc.JARMKeyEncryptionAlgorithm != "" || dc.JARMContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"jarm encryption is not supported")
		}
		return nil
	}

	if dc.JARMKeyEncryptionAlgorithm != "" && !slices.Contains(ctx.JARM.KeyEncrytionAlgorithms, dc.JARMKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg not supported")
	}

	if dc.JARMContentEncryptionAlgorithm != "" && dc.JARMKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dc.JARMContentEncryptionAlgorithm != "" && !slices.Contains(ctx.JARM.ContentEncryptionAlgorithms, dc.JARMContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncryptionAlgorithms(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAR.EncryptionIsEnabled {
		if dc.JARKeyEncryptionAlgorithm != "" || dc.JARContentEncryptionAlgorithm != "" {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"jar encryption is not supported")
		}
		return nil
	}

	if dc.JARKeyEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.JARKeyEncryptionAlgorithms(), dc.JARKeyEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg not supported")
	}

	if dc.JARContentEncryptionAlgorithm != "" && dc.JARKeyEncryptionAlgorithm == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dc.JARContentEncryptionAlgorithm != "" &&
		!slices.Contains(ctx.JAR.ContentEncryptionAlgorithms, dc.JARContentEncryptionAlgorithm) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if dc.PublicJWKS == nil {
		return nil
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(dc.PublicJWKS, &jwks); err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata, "invalid jwks")
	}

	for _, jwk := range jwks.Keys {
		if !jwk.IsPublic() || !jwk.Valid() {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.KeyID))
		}
	}
	return nil
}

func validatePublicJWKSURI(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if !ctx.AuthorizationDetails.IsEnabled || dc.AuthorizationDetailTypes == nil {
		return nil
	}

	for _, dt := range dc.AuthorizationDetailTypes {
		if !slices.Contains(ctx.AuthorizationDetails.Types, dt) {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"authorization detail type not supported")
		}
	}

	return nil
}

func validateRefreshTokenGrant(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	if strutil.ContainsOfflineAccess(dc.Scopes) && !slices.Contains(dc.GrantTypes, goidc.GrantRefreshToken) {
		return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
			"refresh_token grant is required for using the scope offline_access")
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	dc dynamicRequest,
) oidc.Error {
	for _, requestedScope := range strutil.SplitWithSpaces(dc.Scopes) {
		matches := false
		for _, scope := range ctx.Scopes {
			if requestedScope == scope.ID {
				matches = true
				break
			}
		}
		if !matches {
			return oidc.NewError(oidc.ErrorCodeInvalidClientMetadata,
				"scope "+requestedScope+" is not valid")
		}
	}

	return nil
}
