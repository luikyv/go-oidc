package dcr

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

func validateRequest(
	ctx *oidc.Context,
	dc request,
) error {
	return runValidations(
		ctx, dc,
		validateAuthnMethod,
		validateScopes,
		validatePrivateKeyJWT,
		validateSecretJWT,
		validateSelfSignedTLSAuthn,
		validateTLSAuthn,
		validateGrantTypes,
		validateRedirectURIS,
		validateResponseTypes,
		validateOpenIDScopeIfRequired,
		validateSubjectIdentifierType,
		validateIDTokenSigAlg,
		validateIDTokenEncAlgs,
		validateUserInfoSigAlg,
		validateUserInfoEncAlgs,
		validateJARSigAlg,
		validateJAREncAlgs,
		validateJARMSigAlg,
		validateJARMEncAlgs,
		validatePublicJWKS,
		validatePublicJWKSURI,
		validateAuthorizationDetailTypes,
		validateTLSTokenBinding,
	)
}

func runValidations(
	ctx *oidc.Context,
	dc request,
	validations ...func(
		ctx *oidc.Context,
		dc request,
	) error,
) error {
	for _, validation := range validations {
		if err := validation(ctx, dc); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx *oidc.Context,
	dc request,
) error {
	for _, gt := range dc.GrantTypes {
		if !slices.Contains(ctx.GrantTypes, gt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"grant type not allowed")
		}
	}

	if dc.AuthnMethod == goidc.ClientAuthnNone &&
		slices.Contains(dc.GrantTypes, goidc.GrantClientCredentials) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"client_credentials grant type not allowed for a client with no authentication")
	}

	if slices.Contains(dc.GrantTypes, goidc.GrantIntrospection) &&
		!slices.Contains(ctx.IntrospectionClientAuthnMethods, dc.AuthnMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"introspection grant type not allowed for the authentication method requested")
	}

	return nil
}

func validateRedirectURIS(
	ctx *oidc.Context,
	dc request,
) error {
	for _, ru := range dc.RedirectURIs {
		parsedRU, err := url.ParseRequestURI(ru)
		if err != nil {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"invalid redirect uri")
		}
		if parsedRU.Fragment != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"the redirect uri cannot contain a fragment")
		}
	}

	return nil
}

func validateResponseTypes(
	ctx *oidc.Context,
	dc request,
) error {

	for _, rt := range dc.ResponseTypes {
		if !slices.Contains(ctx.ResponseTypes, rt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"response type not allowed")
		}
	}

	if !slices.Contains(dc.GrantTypes, goidc.GrantImplicit) {
		for _, rt := range dc.ResponseTypes {
			if rt.IsImplicit() {
				return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
					"implicit grant type is required for implicit response types")
			}
		}
	}

	if !slices.Contains(dc.GrantTypes, goidc.GrantAuthorizationCode) {
		for _, rt := range dc.ResponseTypes {
			if rt.Contains(goidc.ResponseTypeCode) {
				return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
					"authorization code grant type is required for code response types")
			}
		}
	}

	return nil
}

func validateAuthnMethod(
	ctx *oidc.Context,
	dc request,
) error {
	if !slices.Contains(ctx.ClientAuthnMethods, dc.AuthnMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authn method not allowed")
	}
	return nil
}

func validateOpenIDScopeIfRequired(
	ctx *oidc.Context,
	dc request,
) error {
	if !ctx.OpenIDIsRequired {
		return nil
	}

	if dc.ScopeIDs != "" || !strutil.ContainsOpenID(dc.ScopeIDs) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"scope openid is required")
	}

	return nil
}

func validateSubjectIdentifierType(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.SubIdentifierType == "" {
		return nil
	}

	if !slices.Contains(ctx.SubIdentifierTypes, dc.SubIdentifierType) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"subject_type not supported")
	}
	return nil
}

func validateIDTokenSigAlg(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.IDTokenSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSigAlgs(), dc.IDTokenSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSigAlg(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.UserInfoSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSigAlgs(), dc.UserInfoSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSigAlg(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.JARSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JARSigAlgs, dc.JARSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSigAlg(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.JARMSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JARMSigAlgs(), dc.JARMSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_signed_response_alg not supported")
	}
	return nil
}

func validatePrivateKeyJWT(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dc.AuthnSigAlg != "" && !slices.Contains(ctx.PrivateKeyJWTSigAlgs, dc.AuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported for private_key_jwt")
	}

	if dc.PublicJWKS == nil && dc.PublicJWKSURI == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"the jwks is required for private_key_jwt")
	}

	return nil
}

func validateSecretJWT(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnSecretJWT {
		return nil
	}

	if dc.AuthnSigAlg != "" && !slices.Contains(ctx.ClientSecretJWTSigAlgs, dc.AuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported for client_secret_jwt")
	}
	return nil
}

func validateSelfSignedTLSAuthn(
	_ *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnSelfSignedTLS {
		return nil
	}

	if dc.PublicJWKSURI == "" && dc.PublicJWKS == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSAuthn(
	_ *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnTLS {
		return nil
	}

	numberOfIdentifiers := 0

	if dc.TLSSubDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if dc.TLSSubAlternativeName != "" {
		numberOfIdentifiers++
	}

	if dc.TLSSubAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncAlgs(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if ID token encryption is not enabled, but the client
	// requested it.
	if !ctx.UserEncIsEnabled {
		if dc.IDTokenKeyEncAlg != "" || dc.IDTokenContentEncAlg != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"ID token encryption is not supported")
		}
		return nil
	}

	if dc.IDTokenKeyEncAlg != "" &&
		!slices.Contains(ctx.UserKeyEncAlgs, dc.IDTokenKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg not supported")
	}

	if dc.IDTokenContentEncAlg != "" && dc.IDTokenKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dc.IDTokenContentEncAlg != "" &&
		!slices.Contains(ctx.UserContentEncAlgs, dc.IDTokenContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncAlgs(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if user info encryption is not enabled, but the client
	// requested it.
	if !ctx.UserEncIsEnabled {
		if dc.UserInfoKeyEncAlg != "" || dc.UserInfoContentEncAlg != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"user info encryption is not supported")
		}
		return nil
	}

	if dc.UserInfoKeyEncAlg != "" &&
		!slices.Contains(ctx.UserKeyEncAlgs, dc.UserInfoKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg not supported")
	}

	if dc.UserInfoContentEncAlg != "" && dc.UserInfoKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dc.UserInfoContentEncAlg != "" &&
		!slices.Contains(ctx.UserContentEncAlgs, dc.UserInfoContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncAlgs(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARMIsEnabled {
		if dc.JARMKeyEncAlg != "" || dc.JARMContentEncAlg != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"jarm encryption is not supported")
		}
		return nil
	}

	if dc.JARMKeyEncAlg != "" &&
		!slices.Contains(ctx.JARMKeyEncAlgs, dc.JARMKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg not supported")
	}

	if dc.JARMContentEncAlg != "" && dc.JARMKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dc.JARMContentEncAlg != "" &&
		!slices.Contains(ctx.JARMContentEncAlgs, dc.JARMContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncAlgs(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAREncIsEnabled {
		if dc.JARKeyEncAlg != "" || dc.JARContentEncAlg != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"jar encryption is not supported")
		}
		return nil
	}

	if dc.JARKeyEncAlg != "" &&
		!slices.Contains(ctx.JARKeyEncAlgs(), dc.JARKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg not supported")
	}

	if dc.JARContentEncAlg != "" && dc.JARKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dc.JARContentEncAlg != "" &&
		!slices.Contains(ctx.JARContentEncAlgs, dc.JARContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.PublicJWKS == nil {
		return nil
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(dc.PublicJWKS, &jwks); err != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "invalid jwks")
	}

	for _, jwk := range jwks.Keys {
		if !jwk.IsPublic() || !jwk.Valid() {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				fmt.Sprintf("the key with ID: %s jwks is invalid", jwk.KeyID))
		}
	}
	return nil
}

func validatePublicJWKSURI(
	ctx *oidc.Context,
	dc request,
) error {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx *oidc.Context,
	dc request,
) error {
	if !ctx.AuthDetailsIsEnabled || dc.AuthDetailTypes == nil {
		return nil
	}

	for _, dt := range dc.AuthDetailTypes {
		if !slices.Contains(ctx.AuthDetailTypes, dt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"authorization detail type not supported")
		}
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	dc request,
) error {
	for _, requestedScope := range strutil.SplitWithSpaces(dc.ScopeIDs) {
		if err := validateScope(ctx, requestedScope); err != nil {
			return err
		}
	}

	return nil
}

func validateScope(ctx *oidc.Context, requestedScope string) error {
	for _, scope := range ctx.Scopes {
		if requestedScope == scope.ID {
			return nil
		}
	}
	return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
		"scope "+requestedScope+" is not valid")
}

func validateTLSTokenBinding(
	ctx *oidc.Context,
	dc request,
) error {
	if !ctx.MTLSTokenBindingIsEnabled && dc.TLSBoundTokensIsRequired {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"tls_client_certificate_bound_access_tokens is not supported")
	}

	return nil
}
