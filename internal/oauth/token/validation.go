package token

import (
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func validateTokenBindingIsRequired(
	ctx *utils.Context,
) goidc.OAuthError {
	if !ctx.SenderConstrainedTokenIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := ctx.DPoPJWT()
	if ctx.DPoPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, ok = ctx.ClientCertificate()
	if ctx.TLSBoundTokensIsEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDPoP(
	ctx *utils.Context,
	_ utils.TokenRequest,
	client *goidc.Client,
) goidc.OAuthError {

	dpopJWT, ok := ctx.DPoPJWT()
	// Return an error if the DPoP header was not informed, but it's required either in the context or by the client.
	if !ok && (ctx.DPoPIsRequired || client.DPoPIsRequired) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed, we just ignore it.
	if !ctx.DPoPIsEnabled || !ok {
		return nil
	}

	return utils.ValidateDPoPJWT(ctx, dpopJWT, utils.DPoPJWTValidationOptions{})
}
