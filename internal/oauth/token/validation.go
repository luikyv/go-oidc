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
