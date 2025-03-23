package provider

import (
	"errors"

	"github.com/luikyv/go-oidc/internal/oidc"
)

func validateTokenBinding(config oidc.Configuration) error {
	if config.TokenBindingIsRequired &&
		!config.DPoPIsEnabled &&
		!config.MTLSTokenBindingIsEnabled {
		return errors.New("if sender constraining tokens is required, at least one mechanism must be enabled, either DPoP or TLS")
	}

	return nil
}

func runValidations(config oidc.Configuration, validators ...func(oidc.Configuration) error) error {
	for _, validator := range validators {
		if err := validator(config); err != nil {
			return err
		}
	}
	return nil
}
