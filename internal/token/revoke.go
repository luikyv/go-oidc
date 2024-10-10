package token

import (
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func revoke(ctx oidc.Context, req queryRequest) error {
	client, err := clientutil.Authenticated(ctx, clientutil.TokenRevocationAuthnContext)
	if err != nil {
		return err
	}

	if !ctx.IsClientAllowedTokenRevocation(client) {
		return goidc.NewError(goidc.ErrorCodeAccessDenied,
			"client not allowed to revoke tokens")
	}

	info, err := IntrospectionInfo(ctx, req.token)
	// If the token was not found, is expired, etc., there's no point in
	// revoking it.
	if err != nil {
		return nil
	}

	if client.ID != info.ClientID {
		return goidc.NewError(goidc.ErrorCodeAccessDenied,
			"token was not issued for this client")
	}

	_ = ctx.DeleteGrantSession(info.GrantID)
	return nil
}
