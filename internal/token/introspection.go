package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func IntrospectionInfo(ctx oidc.Context, tkn string) (goidc.TokenInfo, error) {
	info, err := func() (goidc.TokenInfo, error) {
		id, err := ExtractID(ctx, tkn)
		if err != nil {
			return goidc.TokenInfo{IsActive: false}, nil
		}

		token, err := ctx.TokenByID(id)
		if err != nil {
			return goidc.TokenInfo{}, fmt.Errorf("error fetching token: %w", err)
		}

		if token.IsExpired() {
			return goidc.TokenInfo{IsActive: false}, nil
		}

		grant, err := ctx.Grant(token.GrantID)
		if err != nil {
			return goidc.TokenInfo{}, fmt.Errorf("error fetching grant: %w", err)
		}

		if grant.IsExpired() {
			return goidc.TokenInfo{IsActive: false}, nil
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
		}, nil
	}()
	if err == nil {
		return info, nil
	}
	if !errors.Is(err, goidc.ErrNotFound) {
		return goidc.TokenInfo{}, err
	}
	if !slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.TokenInfo{IsActive: false}, nil
	}

	// If the token is not found as an access token, try fetching it as a refresh token.
	info, err = func() (goidc.TokenInfo, error) {
		grant, err := ctx.RefreshGrantByRefreshToken(tkn)
		if err != nil {
			return goidc.TokenInfo{}, fmt.Errorf("token not found: %w", err)
		}

		if grant.IsExpired() {
			return goidc.TokenInfo{IsActive: false}, nil
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
			ExpiresAt:         grant.ExpiresAt,
			Confirmation:      cnf,
			ResourceAudiences: grant.Resources,
		}, nil
	}()
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.TokenInfo{IsActive: false}, nil
		}
		return goidc.TokenInfo{}, err
	}

	return info, nil
}

func introspect(ctx oidc.Context, req queryRequest) (goidc.TokenInfo, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextTokenIntrospection)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if req.token == "" {
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "token is missing")
	}

	// The information of an invalid token must not be sent as an error.
	// It will be returned as the default value of [goidc.TokenInfo] with the
	// field is_active as false.
	info, err := IntrospectionInfo(ctx, req.token)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if info.IsActive && !ctx.TokenIntrospectionIsClientAllowed(c, info) {
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "client not allowed to introspect the token")
	}

	return info, nil
}
