package introspection

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func IntrospectToken(
	ctx utils.Context,
	req utils.TokenIntrospectionRequest,
) (
	utils.TokenIntrospectionInfo,
	goidc.OAuthError,
) {
	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientId))
		return utils.TokenIntrospectionInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return utils.TokenIntrospectionInfo{}, err
	}

	resp := getTokenIntrospectionInfo(ctx, req.Token)
	if !resp.IsActive && resp.ClientId != client.Id {
		return utils.TokenIntrospectionInfo{}, goidc.NewOAuthError(goidc.InvalidClient, "invalid token")
	}

	return utils.TokenIntrospectionInfo{}, nil
}
