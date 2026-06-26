package token

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Revoke(ctx oidc.Context, tkn string, c *goidc.Client) error {
	if joseutil.IsJWS(tkn) {
		if !ctx.TokenRevocationRevokeGrantOnAccessTokenEnabled {
			return nil
		}

		algs, err := ctx.SigAlgs()
		if err != nil {
			return fmt.Errorf("could not fetch signature algorithms: %w", err)
		}

		parsedToken, err := jwt.ParseSigned(tkn, algs)
		if err != nil {
			return nil //nolint:nilerr
		}

		if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
			return nil
		}

		keyID := parsedToken.Headers[0].KeyID
		publicKey, err := ctx.PublicJWK(keyID)
		if err != nil || publicKey.Use != string(goidc.KeyUsageSignature) {
			return nil //nolint:nilerr
		}

		var claims jwt.Claims
		var info goidc.TokenInfo
		if err := parsedToken.Claims(publicKey.Key, &claims, &info); err != nil {
			return nil //nolint:nilerr
		}

		if err := claims.ValidateWithLeeway(jwt.Expected{
			Issuer: ctx.Issuer(),
		}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
			return nil //nolint:nilerr
		}

		if c != nil && c.ID != info.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		grant, err := ctx.Grant(info.GrantID)
		if err != nil {
			if errors.Is(err, goidc.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("could not fetch the grant for token revocation: %w", err)
		}

		if grant.RevokedAt != 0 {
			return nil
		}

		grant.RevokedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(grant); err != nil {
			return fmt.Errorf("could not save grant: %w", err)
		}
		return nil
	}

	// Opaque access token revocation.
	err := func() error {
		if !ctx.OpaqueTokenEnabled {
			return goidc.ErrNotFound
		}

		token, err := ctx.OpaqueToken(tkn)
		if err != nil {
			return fmt.Errorf("could not fetch token: %w", err)
		}

		if timeutil.TimestampNow() >= token.ExpiresAt || token.RevokedAt != 0 {
			return nil
		}

		if c != nil && c.ID != token.ClientID {
			return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the token belongs to a different client"))
		}

		if !ctx.TokenRevocationRevokeGrantOnAccessTokenEnabled {
			token.RevokedAt = timeutil.TimestampNow()
			if err := ctx.SaveOpaqueToken(token); err != nil {
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

		if grant.RefreshTokenExpiresAt != 0 && timeutil.TimestampNow() >= grant.RefreshTokenExpiresAt {
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
