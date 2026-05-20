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

func Revoke(ctx oidc.Context, tkn string, c *goidc.Client) error {
	// Access token revocation.
	err := func() error {
		id, err := ExtractID(ctx, tkn)
		if err != nil {
			return nil //nolint:nilerr
		}

		token, err := ctx.Token(id)
		if err != nil {
			return fmt.Errorf("could not fetch token: %w", err)
		}

		if timeutil.TimestampNow() >= token.ExpiresAt || token.RevokedAt != 0 {
			return nil
		}

		if c != nil && c.ID != token.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		if !ctx.TokenRevocationDeleteGrantOnAccessTokenIsEnabled {
			token.RevokedAt = timeutil.TimestampNow()
			if err := ctx.SaveToken(token); err != nil {
				return fmt.Errorf("could not revoke token: %w", err)
			}
			return nil
		}

		grant, err := ctx.Grant(token.GrantID)
		if err != nil {
			return fmt.Errorf("could not fetch grant: %w", err)
		}

		grant.RevokedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return fmt.Errorf("could not save grant: %w", err)
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

	// Refresh token revocation.
	err = func() error {
		grant, err := ctx.RefreshGrantByRefreshToken(tkn)
		if err != nil {
			return fmt.Errorf("could not fetch grant by refresh token: %w", err)
		}

		if timeutil.TimestampNow() >= grant.RefreshTokenExpiresAt {
			return nil
		}

		if grant.RevokedAt != 0 {
			return nil
		}

		if c != nil && c.ID != grant.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		grant.RevokedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return fmt.Errorf("could not save grant: %w", err)
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

	return Revoke(ctx, req.token, c)
}
