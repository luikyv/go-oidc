package token

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateTokenBindingIsRequired(
	ctx utils.OAuthContext,
) goidc.OAuthError {
	if !ctx.SenderConstrainedTokenIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := ctx.GetDPOPJWT()
	if ctx.DPOPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, ok = ctx.GetClientCertificate()
	if ctx.TLSBoundTokensIsEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDPOP(
	ctx utils.OAuthContext,
	_ utils.TokenRequest,
	client goidc.Client,
) goidc.OAuthError {

	dpopJWT, ok := ctx.GetDPOPJWT()
	// Return an error if the DPoP header was not informed, but it's required either in the context or by the client.
	if !ok && (ctx.DPOPIsRequired || client.DPOPIsRequired) {
		ctx.Logger.Debug("The DPoP header is required, but wasn't provided")
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed, we just ignore it.
	if !ctx.DPOPIsEnabled || !ok {
		return nil
	}

	return utils.ValidateDPOPJWT(ctx, dpopJWT, utils.DPOPJWTValidationOptions{})
}
