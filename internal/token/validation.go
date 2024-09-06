package token

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateTokenBinding(ctx *oidc.Context, client *goidc.Client) error {
	if err := validateTokenBindingDPoP(ctx, client); err != nil {
		return err
	}

	if err := validateTokenBindingTLS(ctx, client); err != nil {
		return err
	}

	return validateTokenBindingIsRequired(ctx)
}

func validateTokenBindingDPoP(
	ctx *oidc.Context,
	client *goidc.Client,
) error {

	if !ctx.DPoPIsEnabled {
		return nil
	}

	dpopJWT, ok := dpopJWT(ctx)
	// Return an error if the DPoP header was not informed, but it's required
	// either in the general config or by the client.
	if !ok && (ctx.DPoPIsRequired || client.DPoPIsRequired) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid dpop header")
	}

	// If the DPoP header was not informed, there's nothing to validate.
	if !ok {
		return nil
	}
	return validateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{})
}

func validateTokenBindingTLS(
	ctx *oidc.Context,
	client *goidc.Client,
) error {
	if !ctx.MTLSTokenBindingIsEnabled {
		return nil
	}

	_, err := ctx.ClientCert()
	if err != nil && (ctx.MTLSTokenBindingIsRequired || client.TLSBoundTokensIsRequired) {
		return oidcerr.Errorf(oidcerr.CodeInvalidRequest, "invalid client certificate", err)
	}

	return nil
}

func validateTokenBindingIsRequired(ctx *oidc.Context) error {
	if !ctx.TokenBindingIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := dpopJWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err != nil {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"token binding is required either with dpop or tls")
	}

	return nil
}
