package provider

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func runValidations(
	provider provider,
	validators ...func(provider) error,
) error {
	for _, validator := range validators {
		if err := validator(provider); err != nil {
			return err
		}
	}
	return nil
}

func validateJWKS(provider provider) error {
	for _, key := range provider.config.PrivateJWKS.Keys {
		if !key.Valid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.KeyID)
		}
	}

	return nil
}

func validateSignatureKeys(provider provider) error {

	for _, keyID := range slices.Concat(
		[]string{provider.config.User.DefaultSignatureKeyID},
		provider.config.User.SigKeyIDs,
		provider.config.JARM.SigKeyIDs,
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

func validateEncryptionKeys(provider provider) error {
	for _, keyID := range slices.Concat(
		provider.config.JAR.KeyEncIDs,
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

func validatePrivateKeyJWTSignatureAlgorithms(provider provider) error {
	for _, signatureAlgorithm := range provider.config.ClientAuthn.PrivateKeyJWTSigAlgs {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	return nil
}

func validateClientSecretJWTSignatureAlgorithms(provider provider) error {
	for _, signatureAlgorithm := range provider.config.ClientAuthn.ClientSecretJWTSigAlgs {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	return nil
}

func validateIntrospectionClientAuthnMethods(provider provider) error {

	if !provider.config.Introspection.IsEnabled {
		return nil
	}

	if !slices.Contains(provider.config.ClientAuthn.Methods, goidc.ClientAuthnNone) {
		return errors.New("none client authentication method not allowed for token introspection")
	}

	for _, method := range provider.config.Introspection.ClientAuthnMethods {
		if !slices.Contains(provider.config.ClientAuthn.Methods, method) {
			return errors.New("invalid client authentication method for token introspection")
		}
	}

	return nil
}

func validateJAREncryption(provider provider) error {
	if provider.config.JAR.EncIsEnabled && !provider.config.JAR.IsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	return nil
}

func validateJARMEncryption(provider provider) error {
	if provider.config.JARM.EncIsEnabled && !provider.config.JARM.IsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	return nil
}

func validateTokenBinding(provider provider) error {
	if provider.config.TokenBindingIsRequired &&
		!provider.config.DPoP.IsEnabled &&
		!provider.config.MTLS.TokenBindingIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func validateOpenIDProfile(provider provider) error {
	if provider.config.Profile != goidc.ProfileOpenID {
		return nil
	}

	defaultIDTokenSignatureKey := provider.config.PrivateJWKS.Key(provider.config.User.DefaultSignatureKeyID)[0]
	if defaultIDTokenSignatureKey.Algorithm != string(jose.RS256) {
		return errors.New("the default signature algorithm for ID tokens must be RS256")
	}

	if provider.config.JARM.IsEnabled {
		defaultJARMSignatureKey := provider.config.PrivateJWKS.Key(provider.config.JARM.DefaultSigKeyID)[0]
		if defaultJARMSignatureKey.Algorithm != string(jose.RS256) {
			return errors.New("the default signature algorithm for JARM must be RS256")
		}
	}

	return nil
}

func validateFAPI2Profile(provider provider) error {
	if provider.config.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	// Validate the authentication methods.
	if slices.ContainsFunc(provider.config.ClientAuthn.Methods, func(authnMethod goidc.ClientAuthnType) bool {
		return authnMethod != goidc.ClientAuthnPrivateKeyJWT && authnMethod != goidc.ClientAuthnTLS
	}) {
		return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantImplicit) {
		return errors.New("the implict grant is not allowed for FAPI 2.0")
	}

	if !provider.config.PAR.IsEnabled || !provider.config.PAR.IsRequired {
		return errors.New("pushed authorization requests is required for FAPI 2.0")
	}

	if !provider.config.PKCE.IsEnabled || !provider.config.PKCE.IsRequired {
		return errors.New("proof key for code exchange is required for FAPI 2.0")
	}

	if !provider.config.IssuerRespParamIsEnabled {
		return errors.New("the issuer response parameter is required for FAPI 2.0")
	}

	if slices.Contains(provider.config.GrantTypes, goidc.GrantRefreshToken) &&
		provider.config.RefreshToken.RotationIsEnabled {
		// FAPI 2.0 says that, when rotation is enabled, the old refresh tokens must still be valid. Here, we just forget the old refresh tokens.
		return errors.New("refresh token rotation is not implemented according to FAPI 2.0, so it shouldn't be enabled when using this profile")
	}

	return nil
}
