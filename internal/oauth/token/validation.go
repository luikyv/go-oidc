package token

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateTokenBindingIsRequired(
	ctx utils.Context,
) models.OAuthError {
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
		return models.NewOAuthError(constants.InvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateTokenBindingRequestWithDpop(
	ctx utils.Context,
	_ models.TokenRequest,
	client models.Client,
) models.OAuthError {

	dpopJwt, ok := ctx.GetDpopJwt()
	// Return an error if the DPoP header was not informed, but it's required either in the context or by the client.
	if !ok && (ctx.DpopIsRequired || client.DpopIsRequired) {
		ctx.Logger.Debug("The DPoP header is required, but wasn't provided")
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop header")
	}

	// If DPoP is not enabled or, if it is, but the DPoP header was not informed, we just ignore it.
	if !ctx.DpopIsEnabled || !ok {
		return nil
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, models.DpopJwtValidationOptions{})
}
