package introspection

import (
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func IntrospectToken(
	ctx *utils.Context,
	req utils.TokenIntrospectionRequest,
) (
	goidc.TokenInfo,
	goidc.OAuthError,
) {
	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return goidc.TokenInfo{}, err
	}

	return TokenIntrospectionInfo(ctx, req.Token), nil
}
