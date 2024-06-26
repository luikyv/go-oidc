package token

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateTokenBindingIsRequired(
	ctx utils.Context,
) goidc.OAuthError {
	if !ctx.SenderConstrainedTokenIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := ctx.GetDpopJwt()
	if ctx.DpopIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, ok = ctx.GetClientCertificate()
	if ctx.TlsBoundTokensIsEnabled && ok {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDpop(
	ctx utils.Context,
	_ utils.TokenRequest,
	client goidc.Client,
) goidc.OAuthError {

	dpopJwt, ok := ctx.GetDpopJwt()
	// Return an error if the DPoP header was not informed, but it's required either in the context or by the client.
	if !ok && (ctx.DpopIsRequired || client.DpopIsRequired) {
		ctx.Logger.Debug("The DPoP header is required, but wasn't provided")
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed, we just ignore it.
	if !ctx.DpopIsEnabled || !ok {
		return nil
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, utils.DpopJwtValidationOptions{})
}
