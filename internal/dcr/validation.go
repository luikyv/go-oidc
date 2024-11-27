package dcr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validate(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	return runValidations(
		ctx, meta,
		validateTokenAuthnMethod,
		validateTokenIntrospection,
		validateTokenRevocation,
		validateScopes,
		validatePrivateKeyJWT,
		validateSecretJWT,
		validateSelfSignedTLSAuthn,
		validateTLSAuthn,
		validateGrantTypes,
		validateClientCredentialsGrantType,
		validateRedirectURIS,
		validateRequestURIS,
		validateResponseTypes,
		validateImplicitResponseTypes,
		validateResponseTypeCode,
		validateOpenIDScopeIfRequired,
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
		validateSubjectIdentifierType,
		validateSubIdentifierPairwise,
		validateSectorIdentifierURI,
		validateCIBAGrant,
		validateCIBATokenDeliveryModes,
		validateCIBATokenNotificationEndpoint,
		validateCIBAUserCodeParam,
		validateCIBAJARAlgs,
	)
}

func runValidations(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
	validations ...func(
		ctx oidc.Context,
		meta *goidc.ClientMetaInfo,
	) error,
) error {
	for _, validation := range validations {
		if err := validation(ctx, meta); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantTypes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	for _, gt := range meta.GrantTypes {
		if !slices.Contains(ctx.GrantTypes, gt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"grant type not allowed")
		}
	}

	return nil
}

func validateClientCredentialsGrantType(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if slices.Contains(meta.GrantTypes, goidc.GrantClientCredentials) &&
		meta.TokenAuthnMethod == goidc.ClientAuthnNone {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"client_credentials grant type not allowed for a client with no authentication")
	}

	return nil
}

func validateRedirectURIS(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	for _, ru := range meta.RedirectURIs {
		if parsedRU, err := url.Parse(ru); err != nil ||
			parsedRU.Scheme != "https" ||
			parsedRU.Host == "" ||
			parsedRU.Fragment != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				fmt.Sprintf("invalid redirect uri %s", ru))
		}
	}

	return nil
}

func validateRequestURIS(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	if !ctx.JARByReferenceIsEnabled {
		return nil
	}

	for _, ru := range meta.RequestURIs {
		if err := validateURL("request_uri", ru); err != nil {
			return err
		}
	}

	return nil
}

func validateResponseTypes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	for _, rt := range meta.ResponseTypes {
		if !slices.Contains(ctx.ResponseTypes, rt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"response type not allowed")
		}
	}

	return nil
}

func validateImplicitResponseTypes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	if slices.Contains(meta.GrantTypes, goidc.GrantImplicit) {
		return nil
	}

	for _, rt := range meta.ResponseTypes {
		if rt.IsImplicit() {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"implicit grant type is required for implicit response types")
		}
	}

	return nil
}

func validateResponseTypeCode(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	if slices.Contains(meta.GrantTypes, goidc.GrantAuthorizationCode) {
		return nil
	}

	for _, rt := range meta.ResponseTypes {
		if rt.Contains(goidc.ResponseTypeCode) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"authorization code grant type is required for code response types")
		}
	}

	return nil
}

func validateTokenAuthnMethod(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.TokenAuthnMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.TokenAuthnMethods, meta.TokenAuthnMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token authn method not allowed")
	}
	return nil
}

func validateTokenIntrospection(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.TokenIntrospectionAuthnMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.TokenIntrospectionAuthnMethods, meta.TokenIntrospectionAuthnMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token introspection authn method not allowed")
	}
	return nil
}

func validateTokenRevocation(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.TokenRevocationAuthnMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.TokenRevocationAuthnMethods, meta.TokenRevocationAuthnMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token introspection authn method not allowed")
	}
	return nil
}

func validateOpenIDScopeIfRequired(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.OpenIDIsRequired {
		return nil
	}

	if !strutil.ContainsOpenID(meta.ScopeIDs) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"scope openid is required")
	}

	return nil
}

func validateSubjectIdentifierType(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.SubIdentifierType == "" {
		return nil
	}

	if !slices.Contains(ctx.SubIdentifierTypes, meta.SubIdentifierType) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"subject_type not supported")
	}
	return nil
}

func validateSubIdentifierPairwise(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {

	isPairwise := meta.SubIdentifierType == "" && ctx.DefaultSubIdentifierType == goidc.SubIdentifierPairwise
	isPairwise = isPairwise || meta.SubIdentifierType == goidc.SubIdentifierPairwise
	if !isPairwise {
		return nil
	}

	// When the sector identifier uri is not provided, and the client is using
	// the authorization code or implicit grant types, it is necessary to enforce
	// restrictions on redirect URIs.
	//
	// The logic performs the following steps:
	// 1. Check if SectorIdentifierURI is empty and if the client uses the
	//    authorization code or implicit grant type.
	// 2. Extract the host component of each Redirect URI, ensuring no duplicates.
	// 3. Verify that all Redirect URIs share the same host as this violates the
	// 	  requirements for pairwise sub identifiers without a sector identifier uri.
	if meta.SectorIdentifierURI == "" && slices.ContainsFunc(meta.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		var redirectURIHosts []string
		for _, ru := range meta.RedirectURIs {
			parsedRU, _ := url.Parse(ru)
			if !slices.Contains(redirectURIHosts, parsedRU.Host) {
				redirectURIHosts = append(redirectURIHosts, parsedRU.Host)
			}
		}
		if len(redirectURIHosts) != 1 {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"all redirect URIs must share the same host when using pairwise subject identifier type without specifying a sector identifier uri")
		}
	}

	// If the CIBA grant type is used with non-push modes, `jwks_uri` is required.
	// Also, make sure 'jwks_uri' ownership will be validated at the /bc-authorize
	// endpoint via one of these methods:
	//    - 'private_key_jwt' for token authentication.
	//    - 'self_signed_tls_client_auth' for token authentication.
	//    - Usage of signed request objects.
	if slices.Contains(meta.GrantTypes, goidc.GrantCIBA) && meta.CIBATokenDeliveryMode != goidc.CIBATokenDeliveryModePush {
		if meta.PublicJWKSURI == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"the 'jwks_uri' is required for CIBA with non-push delivery modes when using pairwise sub type")
		}

		jwksURIOwnershipIsGuaranteed := meta.TokenAuthnMethod == goidc.ClientAuthnPrivateKeyJWT
		jwksURIOwnershipIsGuaranteed = jwksURIOwnershipIsGuaranteed || meta.TokenAuthnMethod == goidc.ClientAuthnSelfSignedTLS
		jwksURIOwnershipIsGuaranteed = jwksURIOwnershipIsGuaranteed || meta.CIBAJARSigAlg != ""
		if !jwksURIOwnershipIsGuaranteed {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"the client needs to demonstrate that the 'jwks_uri' belongs to it when using pairwise sub type")
		}
	}

	return nil
}

func validateSectorIdentifierURI(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.SectorIdentifierURI == "" {
		return nil
	}

	if err := validateURL("sector_identifier_uri", meta.SectorIdentifierURI); err != nil {
		return err
	}

	httpClient := ctx.HTTPClient()
	resp, err := httpClient.Get(meta.SectorIdentifierURI)
	if err != nil || resp.StatusCode != http.StatusOK {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata,
			"could not fetch the sector_identifier_uri", err)
	}
	defer resp.Body.Close()

	var uris []string
	if err := json.NewDecoder(resp.Body).Decode(&uris); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata,
			"could not decode the result of sector_identifier_uri", err)
	}

	var wantedURIs []string
	if slices.ContainsFunc(meta.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
	}) {
		wantedURIs = append(wantedURIs, meta.RedirectURIs...)
	}

	if slices.Contains(meta.GrantTypes, goidc.GrantCIBA) {
		if meta.CIBATokenDeliveryMode == goidc.CIBATokenDeliveryModePush {
			wantedURIs = append(wantedURIs, meta.CIBANotificationEndpoint)
		} else if meta.PublicJWKSURI != "" {
			wantedURIs = append(wantedURIs, meta.PublicJWKSURI)
		}
	}

	for _, uri := range wantedURIs {
		if !slices.Contains(uris, uri) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				fmt.Sprintf("the uri %s is not among the ones fetched from sector_identifier_uri", uri))
		}
	}

	return nil
}

func validateIDTokenSigAlg(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.IDTokenSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.IDTokenSigAlgs, meta.IDTokenSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateUserInfoSigAlg(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.UserInfoSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.UserInfoSigAlgs, meta.UserInfoSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_signed_response_alg not supported")
	}
	return nil
}

func validateJARSigAlg(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.JARIsEnabled || meta.JARSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JARSigAlgs, meta.JARSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_signing_alg not supported")
	}
	return nil
}

func validateJARMSigAlg(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.JARMIsEnabled || meta.JARMSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.JARMSigAlgs, meta.JARMSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_signed_response_alg not supported")
	}
	return nil
}

func validatePrivateKeyJWT(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(authnMethods(ctx, meta), goidc.ClientAuthnPrivateKeyJWT) {
		return nil
	}

	if meta.TokenAuthnMethod == goidc.ClientAuthnPrivateKeyJWT &&
		meta.TokenAuthnSigAlg != "" &&
		!slices.Contains(ctx.PrivateKeyJWTSigAlgs, meta.TokenAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported for private_key_jwt")
	}

	if meta.TokenIntrospectionAuthnMethod == goidc.ClientAuthnPrivateKeyJWT &&
		meta.TokenIntrospectionAuthnSigAlg != "" &&
		!slices.Contains(ctx.PrivateKeyJWTSigAlgs, meta.TokenIntrospectionAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"introspection_endpoint_auth_signing_alg not supported for private_key_jwt")
	}

	if meta.TokenRevocationAuthnMethod == goidc.ClientAuthnPrivateKeyJWT &&
		meta.TokenRevocationAuthnSigAlg != "" &&
		!slices.Contains(ctx.PrivateKeyJWTSigAlgs, meta.TokenRevocationAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"revocation_endpoint_auth_signing_alg not supported for private_key_jwt")
	}

	if meta.PublicJWKS == nil && meta.PublicJWKSURI == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"the jwks is required for private_key_jwt")
	}

	return nil
}

func validateSecretJWT(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.TokenAuthnMethod == goidc.ClientAuthnSecretJWT &&
		meta.TokenAuthnSigAlg != "" &&
		!slices.Contains(ctx.ClientSecretJWTSigAlgs, meta.TokenAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"token_endpoint_auth_signing_alg not supported for client_secret_jwt")
	}

	if meta.TokenIntrospectionAuthnMethod == goidc.ClientAuthnSecretJWT &&
		meta.TokenIntrospectionAuthnSigAlg != "" &&
		!slices.Contains(ctx.ClientSecretJWTSigAlgs, meta.TokenIntrospectionAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"introspection_endpoint_auth_signing_alg not supported for client_secret_jwt")
	}

	if meta.TokenRevocationAuthnMethod == goidc.ClientAuthnSecretJWT &&
		meta.TokenRevocationAuthnSigAlg != "" &&
		!slices.Contains(ctx.ClientSecretJWTSigAlgs, meta.TokenRevocationAuthnSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"revocation_endpoint_auth_signing_alg not supported for client_secret_jwt")
	}
	return nil
}

func validateSelfSignedTLSAuthn(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(authnMethods(ctx, meta), goidc.ClientAuthnSelfSignedTLS) {
		return nil
	}

	if meta.PublicJWKSURI == "" && meta.PublicJWKS == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"jwks is required when authenticating with self signed certificates")
	}

	return nil
}

func validateTLSAuthn(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(authnMethods(ctx, meta), goidc.ClientAuthnTLS) {
		return nil
	}

	numberOfIdentifiers := 0

	if meta.TLSSubDistinguishedName != "" {
		numberOfIdentifiers++
	}

	if meta.TLSSubAlternativeName != "" {
		numberOfIdentifiers++
	}

	if meta.TLSSubAlternativeNameIp != "" {
		numberOfIdentifiers++
	}

	if numberOfIdentifiers != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"only one of: tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_ip must be informed")
	}

	return nil
}

func validateIDTokenEncAlgs(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.IDTokenEncIsEnabled {
		return nil
	}

	if meta.IDTokenKeyEncAlg != "" &&
		!slices.Contains(ctx.IDTokenKeyEncAlgs, meta.IDTokenKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg not supported")
	}

	if meta.IDTokenContentEncAlg != "" && meta.IDTokenKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_alg is required if id_token_encrypted_response_enc is informed")
	}

	if meta.IDTokenContentEncAlg != "" &&
		!slices.Contains(ctx.IDTokenContentEncAlgs, meta.IDTokenContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"id_token_encrypted_response_enc not supported")
	}

	return nil
}

func validateUserInfoEncAlgs(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.UserInfoEncIsEnabled {
		return nil
	}

	if meta.UserInfoKeyEncAlg != "" &&
		!slices.Contains(ctx.UserInfoKeyEncAlgs, meta.UserInfoKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg not supported")
	}

	if meta.UserInfoContentEncAlg != "" && meta.UserInfoKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_alg is required if userinfo_encrypted_response_enc is informed")
	}

	if meta.UserInfoContentEncAlg != "" &&
		!slices.Contains(ctx.UserInfoContentEncAlgs, meta.UserInfoContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"userinfo_encrypted_response_enc not supported")
	}

	return nil
}

func validateJARMEncAlgs(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.JARMIsEnabled {
		return nil
	}

	if meta.JARMKeyEncAlg != "" &&
		!slices.Contains(ctx.JARMKeyEncAlgs, meta.JARMKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg not supported")
	}

	if meta.JARMContentEncAlg != "" && meta.JARMKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_alg is required if authorization_encrypted_response_enc is informed")
	}

	if meta.JARMContentEncAlg != "" &&
		!slices.Contains(ctx.JARMContentEncAlgs, meta.JARMContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"authorization_encrypted_response_enc not supported")
	}

	return nil
}

func validateJAREncAlgs(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.JAREncIsEnabled {
		return nil
	}

	if meta.JARKeyEncAlg != "" &&
		!slices.Contains(ctx.JARKeyEncAlgs, meta.JARKeyEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg not supported")
	}

	if meta.JARContentEncAlg != "" && meta.JARKeyEncAlg == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_alg is required if request_object_encryption_enc is informed")
	}

	if meta.JARContentEncAlg != "" &&
		!slices.Contains(ctx.JARContentEncAlgs, meta.JARContentEncAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"request_object_encryption_enc not supported")
	}

	return nil
}

func validatePublicJWKS(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if meta.PublicJWKS == nil {
		return nil
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(meta.PublicJWKS, &jwks); err != nil {
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
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	// TODO: validate the client jwks uri.
	return nil
}

func validateAuthorizationDetailTypes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.AuthDetailsIsEnabled || meta.AuthDetailTypes == nil {
		return nil
	}

	for _, dt := range meta.AuthDetailTypes {
		if !slices.Contains(ctx.AuthDetailTypes, dt) {
			return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
				"authorization detail type not supported")
		}
	}

	return nil
}

func validateScopes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	for _, requestedScope := range strutil.SplitWithSpaces(meta.ScopeIDs) {
		if err := validateScope(ctx, requestedScope); err != nil {
			return err
		}
	}

	return nil
}

func validateScope(ctx oidc.Context, requestedScope string) error {
	for _, scope := range ctx.Scopes {
		if requestedScope == scope.ID {
			return nil
		}
	}
	return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
		"scope "+requestedScope+" is not valid")
}

func validateCIBAGrant(
	_ oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(meta.GrantTypes, goidc.GrantCIBA) {
		return nil
	}

	if meta.TokenAuthnMethod == goidc.ClientAuthnNone {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"none authn method not allowed for ciba")
	}

	return nil
}

func validateCIBATokenDeliveryModes(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(meta.GrantTypes, goidc.GrantCIBA) {
		return nil
	}

	if meta.CIBATokenDeliveryMode == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"backchannel_token_delivery_mode not allowed")
	}

	if !slices.Contains(ctx.CIBATokenDeliveryModels, meta.CIBATokenDeliveryMode) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"backchannel_token_delivery_mode not allowed")
	}

	return nil
}

func validateCIBATokenNotificationEndpoint(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(meta.GrantTypes, goidc.GrantCIBA) {
		return nil
	}

	if !meta.CIBATokenDeliveryMode.IsNotificationMode() {
		return nil
	}

	if meta.CIBANotificationEndpoint == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"backchannel_client_notification_endpoint is required for ping or push token delivery modes")
	}

	if err := validateURL("backchannel_client_notification_endpoint", meta.CIBANotificationEndpoint); err != nil {
		return err
	}

	return nil
}

func validateURL(field, s string) error {
	parsedRU, err := url.Parse(s)
	if err != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			fmt.Sprintf("could not parse %s", field))
	}

	if parsedRU.Scheme != "https" || parsedRU.Host == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			fmt.Sprintf("%s with value %s is invalid", field, s))
	}

	return nil
}

func validateCIBAUserCodeParam(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !slices.Contains(meta.GrantTypes, goidc.GrantCIBA) {
		return nil
	}

	if !ctx.CIBAUserCodeIsEnabled && meta.CIBAUserCodeIsEnabled {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"backchannel_user_code_parameter not supported")
	}

	return nil
}

func validateCIBAJARAlgs(
	ctx oidc.Context,
	meta *goidc.ClientMetaInfo,
) error {
	if !ctx.CIBAJARIsEnabled || meta.CIBAJARSigAlg == "" {
		return nil
	}

	if !slices.Contains(ctx.CIBAJARSigAlgs, meta.CIBAJARSigAlg) {
		return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata,
			"backchannel_authentication_request_signing_alg not supported")
	}

	return nil
}
