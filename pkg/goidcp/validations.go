package goidcp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/goidc/pkg/goidc"
)

func runValidations(
	provider Provider,
	validators ...func(Provider) error,
) error {
	for _, validator := range validators {
		if err := validator(provider); err != nil {
			return err
		}
	}
	return nil
}

func validateJWKS(provider Provider) error {
	for _, key := range provider.config.PrivateJWKS.Keys {
		if !key.Valid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.KeyID)
		}
	}

	return nil
}

func validateSignatureKeys(provider Provider) error {

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
		if key.Use != string(goidc.KeyUsageSignature) {
			return fmt.Errorf("the key ID: %s is not meant for signing", keyID)
		}

		if strings.HasPrefix(key.Algorithm, "HS") {
			return errors.New("symetric algorithms are not allowed for signing")
		}
	}

	return nil
}

func validateEncryptionKeys(provider Provider) error {
	for _, keyID := range slices.Concat(
		provider.config.JARKeyEncryptionIDs,
	) {
		jwkSlice := provider.config.PrivateJWKS.Key(keyID)
		if len(jwkSlice) != 1 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS or is duplicated", keyID)
		}

		key := jwkSlice[0]
		if key.Use != string(goidc.KeyUsageEncryption) {
			return fmt.Errorf("the key ID: %s is not meant for encryption", keyID)
		}
	}

	return nil
}

func validatePrivateKeyJWTSignatureAlgorithms(provider Provider) error {
	for _, signatureAlgorithm := range provider.config.PrivateKeyJWTSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	return nil
}

func validateClientSecretJWTSignatureAlgorithms(provider Provider) error {
	for _, signatureAlgorithm := range provider.config.ClientSecretJWTSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	return nil
}

func validateIntrospectionClientAuthnMethods(provider Provider) error {
	if provider.config.IntrospectionIsEnabled && (!goidc.ContainsAll(provider.config.ClientAuthnMethods, provider.config.IntrospectionClientAuthnMethods...) ||
		slices.Contains(provider.config.IntrospectionClientAuthnMethods, goidc.ClientAuthnNone)) {
		return errors.New("invalid client authentication method for token introspection")
	}

	return nil
}

func validateUserInfoEncryption(provider Provider) error {
	if provider.config.UserInfoEncryptionIsEnabled && !slices.Contains(provider.config.UserInfoContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for user information")
	}

	return nil
}

func validateJAREncryption(provider Provider) error {
	if provider.config.JAREncryptionIsEnabled && !provider.config.JARIsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	if provider.config.JAREncryptionIsEnabled && !slices.Contains(provider.config.JARContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JAR")
	}

	return nil
}

func validateJARMEncryption(provider Provider) error {
	if provider.config.JARMEncryptionIsEnabled && !provider.config.JARMIsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	if provider.config.JARMEncryptionIsEnabled && !slices.Contains(provider.config.JARMContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JARM")
	}

	return nil
}

func validateTokenBinding(provider Provider) error {
	if provider.config.SenderConstrainedTokenIsRequired && !provider.config.DPoPIsEnabled && !provider.config.TLSBoundTokensIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func validateOpenIDProfile(provider Provider) error {
	if provider.config.Profile != goidc.ProfileOpenID {
		return nil
	}

	defaultIDTokenSignatureKey := provider.config.PrivateJWKS.Key(provider.config.DefaultUserInfoSignatureKeyID)[0]
	if defaultIDTokenSignatureKey.Algorithm != string(jose.RS256) {
		return errors.New("the default signature algorithm for ID tokens must be RS256")
	}

	defaultJARMSignatureKey := provider.config.PrivateJWKS.Key(provider.config.DefaultJARMSignatureKeyID)[0]
	if defaultJARMSignatureKey.Algorithm != string(jose.RS256) {
		return errors.New("the default signature algorithm for JARM must be RS256")
	}

	return nil
}

func validateFAPI2Profile(provider Provider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	// Validate the authentication methods.
	if slices.ContainsFunc(provider.config.ClientAuthnMethods, func(authnMethod goidc.ClientAuthnType) bool {
		// TODO: remove self signed, only for tests.
		return authnMethod != goidc.ClientAuthnPrivateKeyJWT && authnMethod != goidc.ClientAuthnTLS && authnMethod != goidc.ClientAuthnSelfSignedTLS
	}) {
		return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantImplicit) {
		return errors.New("the implict grant is not allowed for FAPI 2.0")
	}

	if !provider.config.PARIsEnabled || !provider.config.PARIsRequired {
		return errors.New("pushed authorization requests is required for FAPI 2.0")
	}

	if !provider.config.PkceIsEnabled || !provider.config.PkceIsRequired {
		return errors.New("proof key for code exchange is required for FAPI 2.0")
	}

	if !provider.config.IssuerResponseParameterIsEnabled {
		return errors.New("the issuer response parameter is required for FAPI 2.0")
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantRefreshToken) && provider.config.ShouldRotateRefreshTokens {
		// FAPI 2.0 says that, when rotation is enabled, the old refresh tokens must still be valid. Here, we just forget the old refresh tokens.
		return errors.New("refresh token rotation is not implemented according to FAPI 2.0, so it shouldn't be enabled when using this profile")
	}

	return nil
}
