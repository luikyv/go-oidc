package dcr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func validateRequest(
	ctx *oidc.Context,
	dc request,
) error {
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
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"grant type not allowed")
		}
	}

	if dc.AuthnMethod == goidc.ClientAuthnNone &&
		slices.Contains(dc.GrantTypes, goidc.GrantClientCredentials) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"client_credentials grant type not allowed for a client with no authentication")
	}

	if slices.Contains(dc.GrantTypes, goidc.GrantIntrospection) &&
		!slices.Contains(ctx.Introspection.ClientAuthnMethods, dc.AuthnMethod) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"introspection grant type not allowed for the authentication method requested")
	}

	return nil
}

func validateRedirectURIS(
	ctx *oidc.Context,
	dc request,
) error {
	for _, ru := range dc.RedirectURIs {
		parsedRU, err := url.Parse(ru)
		if err != nil {
			return oidcerr.New(oidcerr.CodeInvalidRedirectURI,
				"invalid redirect uri")
		}
		if parsedRU.Fragment != "" {
			return oidcerr.New(oidcerr.CodeInvalidRedirectURI,
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
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"response type not allowed")
		}
	}

	if !slices.Contains(ctx.GrantTypes, goidc.GrantImplicit) {
		for _, rt := range dc.ResponseTypes {
			if rt.IsImplicit() {
				return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
					"implicit grant type is required for implicit response types")
			}
		}
	}

	if !slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) {
		for _, rt := range dc.ResponseTypes {
			if rt.Contains(goidc.ResponseTypeCode) {
				return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
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
	if !slices.Contains(ctx.ClientAuthn.Methods, dc.AuthnMethod) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
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

	if dc.Scopes != "" || !strutil.ContainsOpenID(dc.Scopes) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
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
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"subject_type not supported")
	}
	return nil
}

func validateIDTokenSignatureAlgorithm(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.IDTokenSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dc.IDTokenSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSignatureAlgorithm(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.UserInfoSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSignatureAlgorithms(), dc.UserInfoSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSignatureAlgorithm(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.JARSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JAR.SigAlgs, dc.JARSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSignatureAlgorithm(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.JARMSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JARMSignatureAlgorithms(), dc.JARMSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"authorization_signed_response_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForPrivateKeyJWT(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dc.AuthnSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.ClientAuthn.PrivateKeyJWTSigAlgs, dc.AuthnSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateClientSignatureAlgorithmForClientSecretJWT(
	ctx *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnSecretJWT {
		return nil
	}

	if dc.AuthnSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.ClientAuthn.ClientSecretJWTSigAlgs, dc.AuthnSigAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported")
	}
	return nil
}

func validateJWKSAreRequiredForPrivateKeyJWTAuthn(
	_ *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnPrivateKeyJWT {
		return nil
	}

	if dc.PublicJWKS == nil && dc.PublicJWKSURI == "" {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"the jwks is required for private_key_jwt")
	}

	return nil
}

func validateJWKSIsRequiredWhenSelfSignedTLSAuthn(
	_ *oidc.Context,
	dc request,
) error {
	if dc.AuthnMethod != goidc.ClientAuthnSelfSignedTLS {
		return nil
	}

	if dc.PublicJWKSURI == "" && dc.PublicJWKS == nil {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSSubjectInfoWhenTLSAuthn(
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
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncryptionAlgorithms(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if ID token encryption is not enabled, but the client
	// requested it.
	if !ctx.User.EncIsEnabled {
		if dc.IDTokenKeyEncAlg != "" || dc.IDTokenContentEncAlg != "" {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"ID token encryption is not supported")
		}
		return nil
	}

	if dc.IDTokenKeyEncAlg != "" &&
		!slices.Contains(ctx.User.KeyEncAlgs, dc.IDTokenKeyEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"id_token_encrypted_response_alg not supported")
	}

	if dc.IDTokenContentEncAlg != "" && dc.IDTokenKeyEncAlg == "" {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if dc.IDTokenContentEncAlg != "" &&
		!slices.Contains(ctx.User.ContentEncAlg, dc.IDTokenContentEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncryptionAlgorithms(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if user info encryption is not enabled, but the client
	// requested it.
	if !ctx.User.EncIsEnabled {
		if dc.UserInfoKeyEncAlg != "" || dc.UserInfoContentEncAlg != "" {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"user info encryption is not supported")
		}
		return nil
	}

	if dc.UserInfoKeyEncAlg != "" &&
		!slices.Contains(ctx.User.KeyEncAlgs, dc.UserInfoKeyEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg not supported")
	}

	if dc.UserInfoContentEncAlg != "" && dc.UserInfoKeyEncAlg == "" {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if dc.UserInfoContentEncAlg != "" &&
		!slices.Contains(ctx.User.ContentEncAlg, dc.UserInfoContentEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncryptionAlgorithms(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if jarm encryption is not enabled, but the client requested it.
	if !ctx.JARM.IsEnabled {
		if dc.JARMKeyEncAlg != "" || dc.JARMContentEncAlg != "" {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"jarm encryption is not supported")
		}
		return nil
	}

	if dc.JARMKeyEncAlg != "" &&
		!slices.Contains(ctx.JARM.KeyEncAlgs, dc.JARMKeyEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"authorization_encrypted_response_alg not supported")
	}

	if dc.JARMContentEncAlg != "" && dc.JARMKeyEncAlg == "" {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if dc.JARMContentEncAlg != "" &&
		!slices.Contains(ctx.JARM.ContentEncAlgs, dc.JARMContentEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncryptionAlgorithms(
	ctx *oidc.Context,
	dc request,
) error {
	// Return an error if jar encryption is not enabled, but the client requested it.
	if !ctx.JAR.EncIsEnabled {
		if dc.JARKeyEncAlg != "" || dc.JARContentEncAlg != "" {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"jar encryption is not supported")
		}
		return nil
	}

	if dc.JARKeyEncAlg != "" &&
		!slices.Contains(ctx.JARKeyEncryptionAlgorithms(), dc.JARKeyEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"request_object_encryption_alg not supported")
	}

	if dc.JARContentEncAlg != "" && dc.JARKeyEncAlg == "" {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if dc.JARContentEncAlg != "" &&
		!slices.Contains(ctx.JAR.ContentEncAlgs, dc.JARContentEncAlg) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
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
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata, "invalid jwks")
	}

	for _, jwk := range jwks.Keys {
		if !jwk.IsPublic() || !jwk.Valid() {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
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
	if !ctx.AuthDetails.IsEnabled || dc.AuthDetailTypes == nil {
		return nil
	}

	for _, dt := range dc.AuthDetailTypes {
		if !slices.Contains(ctx.AuthDetails.Types, dt) {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"authorization detail type not supported")
		}
	}

	return nil
}

func validateRefreshTokenGrant(
	ctx *oidc.Context,
	dc request,
) error {
	if strutil.ContainsOfflineAccess(dc.Scopes) &&
		!slices.Contains(dc.GrantTypes, goidc.GrantRefreshToken) {
		return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
			"refresh_token grant is required for using the scope offline_access")
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	dc request,
) error {
	for _, requestedScope := range strutil.SplitWithSpaces(dc.Scopes) {
		matches := false
		for _, scope := range ctx.Scopes {
			if requestedScope == scope.ID {
				matches = true
				break
			}
		}
		if !matches {
			return oidcerr.New(oidcerr.CodeInvalidClientMetadata,
				"scope "+requestedScope+" is not valid")
		}
	}

	return nil
}

func isRegistrationAccessTokenValid(c *goidc.Client, token string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(c.HashedRegistrationAccessToken),
		[]byte(token),
	)
	return err == nil
}
