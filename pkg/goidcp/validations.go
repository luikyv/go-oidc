package goidcp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func runValidations(
	provider OpenIDProvider,
	validators ...func(OpenIDProvider) error,
) error {
	for _, validator := range validators {
		if err := validator(provider); err != nil {
			return err
		}
	}
	return nil
}

func validateJWKS(provider OpenIDProvider) error {
	for _, key := range provider.config.PrivateJWKS.Keys {
		if !key.IsValid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.KeyID())
		}
	}

	return nil
}

func validateSignatureKeys(provider OpenIDProvider) error {

	for _, keyID := range slices.Concat(
		[]string{provider.config.DefaultUserInfoSignatureKeyID},
		provider.config.UserInfoSignatureKeyIDs,
		provider.config.JARMSignatureKeyIDs,
	) {
		jwkSlice := provider.config.PrivateJWKS.Key(keyID)
		if len(jwkSlice) != 1 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS or is duplicated", keyID)
		}

		key := jwkSlice[0]
		if key.Usage() != string(goidc.KeyUsageSignature) {
			return fmt.Errorf("the key ID: %s is not meant for signing", keyID)
		}

		if strings.HasPrefix(key.Algorithm(), "HS") {
			return errors.New("symetric algorithms are not allowed for signing")
		}
	}

	return nil
}

func validateEncryptionKeys(provider OpenIDProvider) error {
	for _, keyID := range slices.Concat(
		provider.config.JARKeyEncryptionIDs,
	) {
		jwkSlice := provider.config.PrivateJWKS.Key(keyID)
		if len(jwkSlice) != 1 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS or is duplicated", keyID)
		}

		key := jwkSlice[0]
		if key.Usage() != string(goidc.KeyUsageEncryption) {
			return fmt.Errorf("the key ID: %s is not meant for encryption", keyID)
		}
	}

	return nil
}

func validatePrivateKeyJWTSignatureAlgorithms(provider OpenIDProvider) error {
	for _, signatureAlgorithm := range provider.config.PrivateKeyJWTSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	return nil
}

func validateClientSecretJWTSignatureAlgorithms(provider OpenIDProvider) error {
	for _, signatureAlgorithm := range provider.config.ClientSecretJWTSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	return nil
}

func validateIntrospectionClientAuthnMethods(provider OpenIDProvider) error {
	if provider.config.IntrospectionIsEnabled && (!goidc.ContainsAll(provider.config.ClientAuthnMethods, provider.config.IntrospectionClientAuthnMethods...) ||
		slices.Contains(provider.config.IntrospectionClientAuthnMethods, goidc.ClientAuthnNone)) {
		return errors.New("invalid client authentication method for token introspection")
	}

	return nil
}

func validateUserInfoEncryption(provider OpenIDProvider) error {
	if provider.config.UserInfoEncryptionIsEnabled && !slices.Contains(provider.config.UserInfoContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for user information")
	}

	return nil
}

func validateJAREncryption(provider OpenIDProvider) error {
	if provider.config.JAREncryptionIsEnabled && !provider.config.JARIsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	if provider.config.JAREncryptionIsEnabled && !slices.Contains(provider.config.JARContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JAR")
	}

	return nil
}

func validateJARMEncryption(provider OpenIDProvider) error {
	if provider.config.JARMEncryptionIsEnabled && !provider.config.JARMIsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	if provider.config.JARMEncryptionIsEnabled && !slices.Contains(provider.config.JARMContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JARM")
	}

	return nil
}

func validateTokenBinding(provider OpenIDProvider) error {
	if provider.config.SenderConstrainedTokenIsRequired && !provider.config.DPOPIsEnabled && !provider.config.TLSBoundTokensIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func validateOpenIDDefaultIDTokenSignatureAlgorithm(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileOpenID {
		return nil
	}

	defaultIDTokenSignatureKey := provider.config.PrivateJWKS.Key(provider.config.DefaultUserInfoSignatureKeyID)[0]
	if defaultIDTokenSignatureKey.Algorithm() != string(jose.RS256) {
		return errors.New("the default signature algorithm for ID tokens must be RS256")
	}

	return nil
}

func validateOpenIDDefaultJARMSignatureAlgorithm(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileOpenID || !provider.config.JARMIsEnabled {
		return nil
	}

	defaultJARMSignatureKey := provider.config.PrivateJWKS.Key(provider.config.DefaultJARMSignatureKeyID)[0]
	if defaultJARMSignatureKey.Algorithm() != string(jose.RS256) {
		return errors.New("the default signature algorithm for JARM must be RS256")
	}

	return nil
}

func validateFAPI2ClientAuthnMethods(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if slices.ContainsFunc(provider.config.ClientAuthnMethods, func(authnMethod goidc.ClientAuthnType) bool {
		// TODO: remove self signed, only for tests.
		return authnMethod != goidc.ClientAuthnPrivateKeyJWT && authnMethod != goidc.ClientAuthnTLS && authnMethod != goidc.ClientAuthnSelfSignedTLS
	}) {
		return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
	}

	return nil
}

func validateFAPI2ImplicitGrantIsNotAllowed(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantImplicit) {
		return errors.New("the implict grant is not allowed for FAPI 2.0")
	}

	return nil
}

func validateFAPI2PARIsRequired(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if !provider.config.PARIsEnabled || !provider.config.PARIsRequired {
		return errors.New("pushed authorization requests is required for FAPI 2.0")
	}

	return nil
}

func validateFAPI2PkceIsRequired(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if !provider.config.PkceIsEnabled || !provider.config.PkceIsRequired {
		return errors.New("proof key for code exchange is required for FAPI 2.0")
	}

	return nil
}

func validateFAPI2IssuerResponseParamIsRequired(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if !provider.config.IssuerResponseParameterIsEnabled {
		return errors.New("the issuer response parameter is required for FAPI 2.0")
	}

	return nil
}

func validateFAPI2RefreshTokenRotation(provider OpenIDProvider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantRefreshToken) && provider.config.ShouldRotateRefreshTokens {
		// FAPI 2.0 says that, when rotation is enabled, the old refresh tokens must still be valid. Here, we just forget the old refresh tokens.
		return errors.New("refresh token rotation is not implemented according to FAPI 2.0, so it shouldn't be enabled when using this profile")
	}

	return nil
}
