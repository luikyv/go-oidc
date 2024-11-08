package provider

import (
	"errors"

	"github.com/luikyv/go-oidc/internal/oidc"
)

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
