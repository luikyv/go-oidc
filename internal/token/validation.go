package token

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateTokenBindingIsRequired(
	ctx *oidc.Context,
) error {
	if !ctx.TokenBindingIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := dpopJWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, ok = ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDPoP(
	ctx *oidc.Context,
	_ request,
	client *goidc.Client,
) error {

	dpopJWT, ok := dpopJWT(ctx)
	// Return an error if the DPoP header was not informed, but it's required
	// either in the context or by the client.
	if !ok && (ctx.DPoPIsRequired || client.DPoPIsRequired) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed,
	// we just ignore it.
	if !ctx.DPoPIsEnabled || !ok {
		return nil
	}

	return ValidateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{})
}
