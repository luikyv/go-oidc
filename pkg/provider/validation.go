package provider

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TODO: See what to do with this.
// // ValidateOpenIDCompliance returns an error if the openid provider is not
// // compliante with the openid profile.
// func ValidateOpenIDCompliance(provider provider) error {
// 	defaultUserSigKey := provider.config.PrivateJWKS.Key(
// 		provider.config.UserDefaultSigKeyID,
// 	)[0]
// 	if defaultUserSigKey.Algorithm != string(jose.RS256) {
// 		return errors.New("the default signature algorithm for ID tokens must be RS256")
// 	}

// 	if provider.config.JARMIsEnabled {
// 		defaultJARMSigKey := provider.config.PrivateJWKS.Key(
// 			provider.config.JARMDefaultSigKeyID,
// 		)[0]
// 		if defaultJARMSigKey.Algorithm != string(jose.RS256) {
// 			return errors.New("the default signature algorithm for JARM must be RS256")
// 		}
// 	}

// 	if !provider.config.OutterAuthParamsRequired {
// 		return errors.New("the authorization parameters must be required to be passed as query params during /authorize")
// 	}

// 	return nil
// }

// // ValidateFAPI2Compliance returns an error if the openid provider is not
// // compliante with the FAPI2 profile.
// func ValidateFAPI2Compliance(provider provider) error {
// 	// Validate the authentication methods.
// 	if slices.ContainsFunc(
// 		provider.config.ClientAuthnMethods,
// 		func(authnMethod goidc.ClientAuthnType) bool {
// 			return authnMethod != goidc.ClientAuthnPrivateKeyJWT && authnMethod != goidc.ClientAuthnTLS
// 		},
// 	) {
// 		return errors.New("only private_key_jwt and tls_client_auth are allowed for FAPI 2.0")
// 	}

// 	if slices.Contains(provider.config.GrantTypes, goidc.GrantImplicit) {
// 		return errors.New("the implict grant is not allowed for FAPI 2.0")
// 	}

// 	if !provider.config.PARIsEnabled || !provider.config.PARIsRequired {
// 		return errors.New("pushed authorization request is required for FAPI 2.0")
// 	}

// 	if !provider.config.PKCEIsEnabled || !provider.config.PKCEIsRequired {
// 		return errors.New("proof key for code exchange is required for FAPI 2.0")
// 	}

// 	if !provider.config.IssuerRespParamIsEnabled {
// 		return errors.New("the issuer response parameter is required for FAPI 2.0")
// 	}

// 	if slices.Contains(provider.config.GrantTypes, goidc.GrantRefreshToken) &&
// 		provider.config.RefreshTokenRotationIsEnabled {
// 		// FAPI 2.0 says that, when rotation is enabled, the old refresh tokens
// 		// must still be valid. Here, we just forget the old refresh tokens.
// 		return errors.New("refresh token rotation is not implemented according to FAPI 2.0, so it shouldn't be enabled when using this profile")
// 	}

// 	return nil
// }

func validateJWKS(config oidc.Configuration) error {
	for _, key := range config.PrivateJWKS.Keys {
		if !key.Valid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.KeyID)
		}
	}

	return nil
}

func validateSigKeys(config oidc.Configuration) error {

	for _, keyID := range slices.Concat(
		[]string{config.UserDefaultSigKeyID},
		config.UserSigKeyIDs,
		config.JARMSigKeyIDs,
	) {
		jwkSlice := config.PrivateJWKS.Key(keyID)
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

func validateEncKeys(config oidc.Configuration) error {
	for _, keyID := range slices.Concat(
		config.JARKeyEncIDs,
	) {
		jwkSlice := config.PrivateJWKS.Key(keyID)
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

func validatePrivateKeyJWTSigAlgs(config oidc.Configuration) error {
	for _, signatureAlgorithm := range config.PrivateKeyJWTSigAlgs {
		if strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("symetric algorithms are not allowed for private_key_jwt authentication")
		}
	}

	return nil
}

func validateClientSecretJWTSigAlgs(config oidc.Configuration) error {
	for _, signatureAlgorithm := range config.ClientSecretJWTSigAlgs {
		if !strings.HasPrefix(string(signatureAlgorithm), "HS") {
			return errors.New("assymetric algorithms are not allowed for client_secret_jwt authentication")
		}
	}

	return nil
}

func validateIntrospectionClientAuthnMethods(config oidc.Configuration) error {

	if !config.IntrospectionIsEnabled {
		return nil
	}

	if !slices.Contains(config.IntrospectionClientAuthnMethods, goidc.ClientAuthnNone) {
		return errors.New("none client authentication method not allowed for token introspection")
	}

	for _, method := range config.IntrospectionClientAuthnMethods {
		if !slices.Contains(config.ClientAuthnMethods, method) {
			return errors.New("invalid client authentication method for token introspection")
		}
	}

	return nil
}

func validateJAREnc(config oidc.Configuration) error {
	if config.JAREncIsEnabled && !config.JARIsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	return nil
}

func validateJARMEnc(config oidc.Configuration) error {
	if config.JARMEncIsEnabled && !config.JARMIsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	return nil
}

func validateTokenBinding(config oidc.Configuration) error {
	if config.TokenBindingIsRequired &&
		!config.DPoPIsEnabled &&
		!config.MTLSTokenBindingIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func runValidations(
	config oidc.Configuration,
	validators ...func(oidc.Configuration) error,
) error {
	for _, validator := range validators {
		if err := validator(config); err != nil {
			return err
		}
	}
	return nil
}
