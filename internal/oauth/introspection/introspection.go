package introspection

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func IntrospectToken(
	ctx *utils.Context,
	req utils.TokenIntrospectionRequest,
) (
	utils.TokenIntrospectionInfo,
	goidc.OAuthError,
) {
	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return utils.TokenIntrospectionInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return utils.TokenIntrospectionInfo{}, err
	}

	return tokenIntrospectionInfo(ctx, req.Token), nil
}
