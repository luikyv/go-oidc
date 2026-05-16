package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func revoke(ctx oidc.Context, req queryRequest) error {
	if req.token == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("token is required"))
	}

	c, err := client.Authenticated(ctx, client.AuthnContextTokenRevocation)
	if err != nil {
		return err
	}

	if !ctx.TokenRevocationIsClientAllowed(c) {
		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the client is not allowed to use the revocation endpoint"))
	}

	err = func() error {
		id, err := ExtractID(ctx, req.token)
		if err != nil {
			return nil
		}

		token, err := ctx.Token(id)
		if err != nil {
			return fmt.Errorf("could not fetch token: %w", err)
		}

		if token.IsExpired() {
			return nil
		}

		if c.ID != token.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		if !ctx.TokenRevocationDeleteGrantOnAccessTokenIsEnabled {
			if err := ctx.DeleteToken(token.ID); err != nil {
				return fmt.Errorf("could not delete token: %w", err)
			}
			return nil
		}

		if err := ctx.DeleteGrant(token.GrantID); err != nil {
			return fmt.Errorf("could not delete grant: %w", err)
		}
		if err := ctx.DeleteTokenByGrantID(token.GrantID); err != nil {
			return fmt.Errorf("could not delete tokens by grant id: %w", err)
		}
		return nil
	}()
	if err == nil {
		return nil
	}
	if !errors.Is(err, goidc.ErrNotFound) {
		return err
	}
	if !slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) {
		return nil
	}

	err = func() error {
		grant, err := ctx.RefreshGrantByRefreshToken(req.token)
		if err != nil {
			return fmt.Errorf("could not fetch grant by refresh token: %w", err)
		}

		if timeutil.TimestampNow() > grant.RefreshTokenExpiresAt {
			return nil
		}

		if c.ID != grant.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		if err := ctx.DeleteGrant(grant.ID); err != nil {
			return fmt.Errorf("could not delete grant: %w", err)
		}
		if err := ctx.DeleteTokenByGrantID(grant.ID); err != nil {
			return fmt.Errorf("could not delete tokens by grant id: %w", err)
		}
		return nil
	}()
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nil
		}
		return err
	}

	return nil
}
