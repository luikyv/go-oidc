package provider

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateJWKS(config *oidc.Configuration) error {
	for _, key := range config.PrivateJWKS.Keys {
		if key.KeyID == "" {
			return errors.New("all keys in the JWKS must have an ID")
		}
		if !key.Valid() {
			return fmt.Errorf("the key with ID: %s is not valid", key.KeyID)
		}
	}

	return nil
}

func validateSigKeys(config *oidc.Configuration) error {

	for _, keyAlg := range slices.Concat(
		config.UserSigAlgs,
		config.JARMSigAlgs,
		config.JARSigAlgs,
	) {
		if keyAlg == goidc.NoneSignatureAlgorithm {
			continue
		}
		if strings.HasPrefix(string(keyAlg), "HS") {
			return fmt.Errorf("symetric algorithm %s is not allowed for signing", keyAlg)
		}

		algWasFound := false
		for _, key := range config.PrivateJWKS.Keys {
			if keyAlg == jose.SignatureAlgorithm(key.Algorithm) {
				algWasFound = true
			}
		}

		if !algWasFound {
			return fmt.Errorf("signing algorithm %s has no corresponding key in the JWKS", keyAlg)
		}
	}

	return nil
}

func validateEncKeys(config *oidc.Configuration) error {
	for _, keyAlg := range slices.Concat(
		config.JARKeyEncAlgs,
	) {
		algWasFound := false
		for _, key := range config.PrivateJWKS.Keys {
			if keyAlg == jose.KeyAlgorithm(key.Algorithm) {
				algWasFound = true
			}
		}

		if !algWasFound {
			return fmt.Errorf("encryption algorithm %s has no corresponding key in the JWKS", keyAlg)
		}
	}

	return nil
}

func validateJAREnc(config *oidc.Configuration) error {
	if config.JAREncIsEnabled && !config.JARIsEnabled {
		return errors.New("JAR must be enabled if JAR encryption is enabled")
	}

	return nil
}

func validateJARMEnc(config *oidc.Configuration) error {
	if config.JARMEncIsEnabled && !config.JARMIsEnabled {
		return errors.New("JARM must be enabled if JARM encryption is enabled")
	}

	return nil
}

func validateTokenBinding(config *oidc.Configuration) error {
	if config.TokenBindingIsRequired &&
		!config.DPoPIsEnabled &&
		!config.MTLSTokenBindingIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func runValidations(
	config *oidc.Configuration,
	validators ...func(*oidc.Configuration) error,
) error {
	for _, validator := range validators {
		if err := validator(config); err != nil {
			return err
		}
	}
	return nil
}
