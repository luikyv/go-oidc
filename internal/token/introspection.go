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

func Introspect(ctx oidc.Context, tkn string) (goidc.TokenInfo, *goidc.Grant, error) {
	if joseutil.IsJWS(tkn) {
		algs, err := ctx.SigAlgs()
		if err != nil {
			return goidc.TokenInfo{}, nil, fmt.Errorf("could not fetch signature algorithms: %w", err)
		}

		parsedToken, err := jwt.ParseSigned(tkn, algs)
		if err != nil {
			return goidc.TokenInfo{IsActive: false}, nil, nil //nolint:nilerr
		}

		if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		keyID := parsedToken.Headers[0].KeyID
		publicKey, err := ctx.PublicJWK(keyID)
		if err != nil || publicKey.Use != string(goidc.KeyUsageSignature) {
			return goidc.TokenInfo{IsActive: false}, nil, nil //nolint:nilerr
		}

		var claims jwt.Claims
		var info goidc.TokenInfo
		if err := parsedToken.Claims(publicKey.Key, &claims, &info); err != nil {
			return goidc.TokenInfo{IsActive: false}, nil, nil //nolint:nilerr
		}

		if err := claims.ValidateWithLeeway(jwt.Expected{
			Issuer: ctx.Issuer(),
		}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
			return goidc.TokenInfo{IsActive: false}, nil, nil //nolint:nilerr
		}

		grant, err := ctx.Grant(info.GrantID)
		if err != nil {
			if errors.Is(err, goidc.ErrNotFound) {
				return goidc.TokenInfo{IsActive: false}, nil, nil
			}
			return goidc.TokenInfo{}, nil, fmt.Errorf("could not fetch the grant for token introspection: %w", err)
		}

		if grant.RevokedAt != 0 {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		info.IsActive = true
		info.Username = grant.Username
		info.Type = goidc.TokenTypeBearer
		if info.Confirmation != nil && info.Confirmation.JWKThumbprint != "" {
			info.Type = goidc.TokenTypeDPoP
		}
		return info, grant, nil
	}

	info, grant, err := func() (goidc.TokenInfo, *goidc.Grant, error) {
		if !ctx.OpaqueTokenIsEnabled {
			return goidc.TokenInfo{}, nil, goidc.ErrNotFound
		}

		token, err := ctx.OpaqueToken(tkn)
		if err != nil {
			return goidc.TokenInfo{}, nil, fmt.Errorf("could not fetch the token for introspection: %w", err)
		}

		if timeutil.TimestampNow() >= token.ExpiresAt {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		if token.RevokedAt != 0 {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		grant, err := ctx.Grant(token.GrantID)
		if err != nil {
			return goidc.TokenInfo{}, nil, fmt.Errorf("could not fetch the grant for token introspection: %w", err)
		}

		if grant.RevokedAt != 0 {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		var cnf *goidc.TokenConfirmation
		if token.JWKThumbprint != "" || token.CertThumbprint != "" {
			cnf = &goidc.TokenConfirmation{
				JWKThumbprint:  token.JWKThumbprint,
				CertThumbprint: token.CertThumbprint,
			}
		}

		return goidc.TokenInfo{
			GrantID:           token.GrantID,
			IsActive:          true,
			Issuer:            ctx.Issuer(),
			Subject:           token.Subject,
			Username:          grant.Username,
			Type:              token.Type,
			Scopes:            token.Scopes,
			AuthDetails:       token.AuthDetails,
			ClientID:          token.ClientID,
			IssuedAt:          token.CreatedAt,
			NotBefore:         token.CreatedAt,
			ExpiresAt:         token.ExpiresAt,
			Confirmation:      cnf,
			ResourceAudiences: token.Resources,
			AdditionalClaims:  ctx.TokenClaims(token, grant),
		}, grant, nil
	}()
	if err == nil {
		return info, grant, nil
	}
	if !errors.Is(err, goidc.ErrNotFound) {
		return goidc.TokenInfo{}, nil, err
	}
	if !slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.TokenInfo{IsActive: false}, nil, nil
	}

	// If the token is not found as an access token, try fetching it as a refresh token.
	info, grant, err = func() (goidc.TokenInfo, *goidc.Grant, error) {
		grant, err := ctx.RefreshGrantByRefreshToken(tkn)
		if err != nil {
			return goidc.TokenInfo{}, nil, fmt.Errorf("could not fetch the refresh token grant for introspection: %w", err)
		}

		if grant.RevokedAt != 0 {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		if grant.RefreshTokenExpiresAt != 0 && timeutil.TimestampNow() >= grant.RefreshTokenExpiresAt {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}

		var cnf *goidc.TokenConfirmation
		if grant.JWKThumbprint != "" || grant.CertThumbprint != "" {
			cnf = &goidc.TokenConfirmation{
				JWKThumbprint:  grant.JWKThumbprint,
				CertThumbprint: grant.CertThumbprint,
			}
		}

		return goidc.TokenInfo{
			GrantID:           grant.ID,
			IsActive:          true,
			Issuer:            ctx.Issuer(),
			Subject:           grant.Subject,
			Type:              goidc.TokenTypeBearer,
			Scopes:            grant.Scopes,
			AuthDetails:       grant.AuthDetails,
			ClientID:          grant.ClientID,
			IssuedAt:          grant.CreatedAt,
			NotBefore:         grant.CreatedAt,
			ExpiresAt:         grant.RefreshTokenExpiresAt,
			Confirmation:      cnf,
			ResourceAudiences: grant.Resources,
		}, grant, nil
	}()
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.TokenInfo{IsActive: false}, nil, nil
		}
		return goidc.TokenInfo{}, nil, err
	}

	return info, grant, nil
}

func introspect(ctx oidc.Context, req queryRequest) (goidc.TokenInfo, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextTokenIntrospection)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if req.token == "" {
		return goidc.TokenInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("token is required"))
	}

	// The information of an invalid token must not be sent as an error.
	// It will be returned as the default value of [goidc.TokenInfo] with the
	// field is_active as false.
	info, _, err := Introspect(ctx, req.token)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if info.IsActive && !ctx.TokenIntrospectionIsClientAllowed(c, info) {
		return goidc.TokenInfo{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the client is not allowed to introspect this token"))
	}

	return info, nil
}
