package token

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateTokenBindingIsRequired(
	ctx *oidc.Context,
) oidc.Error {
	if !ctx.TokenBindingIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := ctx.DPoPJWT()
	if ctx.DPoP.IsEnabled && ok {
		tokenWillBeBound = true
	}

	_, ok = ctx.ClientCertificate()
	if ctx.MTLS.TokenBindingIsEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDPoP(
	ctx *oidc.Context,
	_ request,
	client *goidc.Client,
) oidc.Error {

	dpopJWT, ok := ctx.DPoPJWT()
	// Return an error if the DPoP header was not informed, but it's required either in the context or by the client.
	if !ok && (ctx.DPoP.IsRequired || client.DPoPIsRequired) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed, we just ignore it.
	if !ctx.DPoP.IsEnabled || !ok {
		return nil
	}

	return ValidateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{})
}
