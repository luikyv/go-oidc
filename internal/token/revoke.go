package token

import (
	"errors"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func revoke(ctx oidc.Context, req queryRequest) error {
	if req.token == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token parameter is required")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextTokenRevocation)
	if err != nil {
		return err
	}

	if !ctx.TokenRevocationIsClientAllowed(c) {
		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "could not revoke token", errors.New("client not allowed to revoke tokens"))
	}

	info, err := IntrospectionInfo(ctx, req.token)
	// If the token was not found, is expired, etc., there's no point in revoking it.
	if err != nil || !info.IsActive {
		return nil
	}

	if c.ID != info.ClientID {
		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "could not revoke token", errors.New("token was not issued for this client"))
	}

	_ = ctx.DeleteGrant(info.GrantID)
	_ = ctx.DeleteTokenByGrantID(info.GrantID)
	return nil
}
