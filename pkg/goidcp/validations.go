package goidcp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func runValidations(
	provider OpenIdProvider,
	validators ...func(OpenIdProvider) error,
) error {
	for _, validator := range validators {
		if err := validator(provider); err != nil {
			return err
		}
	}
	return nil
}

func validateJwks(provider OpenIdProvider) error {
	for _, key := range provider.config.PrivateJwks.Keys {
		if !key.IsValid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.GetKeyId())
		}
	}

	return nil
}

func validateSignatureKeys(provider OpenIdProvider) error {

	for _, keyId := range slices.Concat(
		[]string{provider.config.DefaultUserInfoSignatureKeyId},
		provider.config.UserInfoSignatureKeyIds,
		provider.config.JarmSignatureKeyIds,
	) {
		jwkSlice := provider.config.PrivateJwks.Key(keyId)
		if len(jwkSlice) != 1 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS or is duplicated", keyId)
		}

		key := jwkSlice[0]
		if key.GetUsage() != string(goidc.KeySignatureUsage) {
			return fmt.Errorf("the key ID: %s is not meant for signing", keyId)
		}

		if strings.HasPrefix(key.GetAlgorithm(), "HS") {
			return errors.New("symetric algorithms are not allowed for signing")
		}
	}

	return nil
}

func validateEncryptionKeys(provider OpenIdProvider) error {
	for _, keyId := range slices.Concat(
		provider.config.JarKeyEncryptionIds,
	) {
		jwkSlice := provider.config.PrivateJwks.Key(keyId)
		if len(jwkSlice) != 1 {
			return fmt.Errorf("the key ID: %s is not present in the server JWKS or is duplicated", keyId)
		}

		key := jwkSlice[0]
		if key.GetUsage() != string(goidc.KeyEncryptionUsage) {
			return fmt.Errorf("the key ID: %s is not meant for encryption", keyId)
		}
	}

	return nil
}

func validatePrivateKeyJwtSignatureAlgorithms(provider OpenIdProvider) error {
	for _, signatureAlgorithm := range provider.config.PrivateKeyJwtSignatureAlgorithms {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	return nil
}

func validateClientSecretJwtSignatureAlgorithms(provider OpenIdProvider) error {
	for _, signatureAlgorithm := range provider.config.ClientSecretJwtSignatureAlgorithms {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	return nil
}

func validateIntrospectionClientAuthnMethods(provider OpenIdProvider) error {
	if provider.config.IntrospectionIsEnabled && (!unit.ContainsAll(provider.config.ClientAuthnMethods, provider.config.IntrospectionClientAuthnMethods...) ||
		slices.Contains(provider.config.IntrospectionClientAuthnMethods, goidc.NoneAuthn)) {
		return errors.New("invalid client authentication method for token introspection")
	}

	return nil
}

func validateUserInfoEncryption(provider OpenIdProvider) error {
	if provider.config.UserInfoEncryptionIsEnabled && !slices.Contains(provider.config.UserInfoContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for user information")
	}

	return nil
}

func validateJarEncryption(provider OpenIdProvider) error {
	if provider.config.JarEncryptionIsEnabled && !provider.config.JarIsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	if provider.config.JarEncryptionIsEnabled && !slices.Contains(provider.config.JarContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JAR")
	}

	return nil
}

func validateJarmEncryption(provider OpenIdProvider) error {
	if provider.config.JarmEncryptionIsEnabled && !provider.config.JarmIsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	if provider.config.JarmEncryptionIsEnabled && !slices.Contains(provider.config.JarmContentEncryptionAlgorithms, jose.A128CBC_HS256) {
		return errors.New("A128CBC-HS256 should be supported as a content key encryption algorithm for JARM")
	}

	return nil
}

func validateTokenBinding(provider OpenIdProvider) error {
	if provider.config.SenderConstrainedTokenIsRequired && !provider.config.DpopIsEnabled && !provider.config.TlsBoundTokensIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func validateOpenIdDefaultIdTokenSignatureAlgorithm(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.OpenIdProfile {
		return nil
	}

	defaultIdTokenSignatureKey := provider.config.PrivateJwks.Key(provider.config.DefaultUserInfoSignatureKeyId)[0]
	if defaultIdTokenSignatureKey.GetAlgorithm() != string(jose.RS256) {
		return errors.New("the default signature algorithm for ID tokens must be RS256")
	}

	return nil
}

func validateOpenIdDefaultJarmSignatureAlgorithm(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.OpenIdProfile || !provider.config.JarmIsEnabled {
		return nil
	}

	defaultJarmSignatureKey := provider.config.PrivateJwks.Key(provider.config.DefaultJarmSignatureKeyId)[0]
	if defaultJarmSignatureKey.GetAlgorithm() != string(jose.RS256) {
		return errors.New("the default signature algorithm for JARM must be RS256")
	}

	return nil
}

func validateFapi2ClientAuthnMethods(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if slices.ContainsFunc(provider.config.ClientAuthnMethods, func(authnMethod goidc.ClientAuthnType) bool {
		// TODO: remove self signed, only for tests.
		return authnMethod != goidc.PrivateKeyJwtAuthn && authnMethod != goidc.TlsAuthn && authnMethod != goidc.SelfSignedTlsAuthn
	}) {
		return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
	}

	return nil
}

func validateFapi2ImplicitGrantIsNotAllowed(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if slices.Contains(provider.config.GrantTypes, goidc.ImplicitGrant) {
		return errors.New("the implict grant is not allowed for FAPI 2.0")
	}

	return nil
}

func validateFapi2ParIsRequired(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if !provider.config.ParIsEnabled || !provider.config.ParIsRequired {
		return errors.New("pushed authorization requests is required for FAPI 2.0")
	}

	return nil
}

func validateFapi2PkceIsRequired(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if !provider.config.PkceIsEnabled || !provider.config.PkceIsRequired {
		return errors.New("proof key for code exchange is required for FAPI 2.0")
	}

	return nil
}

func validateFapi2IssuerResponseParamIsRequired(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if !provider.config.IssuerResponseParameterIsEnabled {
		return errors.New("the issuer response parameter is required for FAPI 2.0")
	}

	return nil
}

func validateFapi2RefreshTokenRotation(provider OpenIdProvider) error {
	if provider.config.Profile != goidc.Fapi2Profile {
		return nil
	}

	if slices.Contains(provider.config.GrantTypes, goidc.RefreshTokenGrant) && provider.config.ShouldRotateRefreshTokens {
		// FAPI 2.0 says that, when rotation is enabled, the old refresh tokens must still be valid. Here, we just forget the old refresh tokens.
		return errors.New("refresh token rotation is not implemented according to FAPI 2.0, so it shouldn't be enabled when using this profile")
	}

	return nil
}
