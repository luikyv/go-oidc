package introspection

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func IntrospectToken(
	ctx utils.OAuthContext,
	req utils.TokenIntrospectionRequest,
) (
	utils.TokenIntrospectionInfo,
	goidc.OAuthError,
) {
	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger().Info("could not authenticate the client", slog.String("client_id", req.ClientID))
		return utils.TokenIntrospectionInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return utils.TokenIntrospectionInfo{}, err
	}

	resp := getTokenIntrospectionInfo(ctx, req.Token)
	if !resp.IsActive && resp.ClientID != client.ID {
		return utils.TokenIntrospectionInfo{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid token")
	}

	return utils.TokenIntrospectionInfo{}, nil
}
