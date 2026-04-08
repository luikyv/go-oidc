package token

import (
	"errors"
	"fmt"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func IntrospectionInfo(ctx oidc.Context, tkn string) (goidc.TokenInfo, error) {
	info, err := accessTokenInfo(ctx, tkn)
	if err == nil {
		return info, nil
	}
	if !errors.Is(err, goidc.ErrNotFound) {
		return goidc.TokenInfo{}, err
	}

	// If the token is not found as an access token, try fetching it as a refresh token.
	info, err = refreshTokenInfo(ctx, tkn)
	if err == nil {
		return info, nil
	}
	if !errors.Is(err, goidc.ErrNotFound) {
		return goidc.TokenInfo{}, err
	}

	return goidc.TokenInfo{IsActive: false}, nil
}

func introspect(ctx oidc.Context, req queryRequest) (goidc.TokenInfo, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextTokenIntrospection)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateIntrospectionRequest(req); err != nil {
		return goidc.TokenInfo{}, err
	}

	// The information of an invalid token must not be sent as an error.
	// It will be returned as the default value of [goidc.TokenInfo] with the
	// field is_active as false.
	tokenInfo, err := IntrospectionInfo(ctx, req.token)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if tokenInfo.IsActive && !ctx.IsClientAllowedTokenIntrospection(c, tokenInfo) {
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "client not allowed to introspect the token")
	}

	return tokenInfo, nil
}

func validateIntrospectionRequest(req queryRequest) error {
	if req.token == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token is missing")
	}
	return nil
}

func refreshTokenInfo(ctx oidc.Context, tkn string) (goidc.TokenInfo, error) {
	grant, err := ctx.GrantByRefreshToken(tkn)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("token not found: %w", err)
	}

	if grant.IsExpired() {
		return goidc.TokenInfo{IsActive: false}, nil
	}

	var cnf *goidc.TokenConfirmation
	if grant.JWKThumbprint != "" || grant.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        grant.JWKThumbprint,
			ClientCertThumbprint: grant.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:              grant.ID,
		IsActive:             true,
		Issuer:               ctx.Issuer(),
		Subject:              grant.Subject,
		Type:                 goidc.TokenTypeBearer,
		Scopes:               grant.Scopes,
		AuthorizationDetails: grant.AuthDetails,
		ClientID:             grant.ClientID,
		IssuedAtTimestamp:    grant.CreatedAtTimestamp,
		NotBeforeTimestamp:   grant.CreatedAtTimestamp,
		ExpiresAtTimestamp:   grant.ExpiresAtTimestamp,
		Confirmation:         cnf,
		ResourceAudiences:    grant.Resources,
	}, nil
}

func accessTokenInfo(ctx oidc.Context, accessToken string) (goidc.TokenInfo, error) {
	id, err := ExtractID(ctx, accessToken)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	token, err := ctx.TokenByID(id)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("token not found: %w", err)
	}

	if token.IsExpired() {
		return goidc.TokenInfo{IsActive: false}, nil
	}

	var cnf *goidc.TokenConfirmation
	if token.JWKThumbprint != "" || token.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        token.JWKThumbprint,
			ClientCertThumbprint: token.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:              token.GrantID,
		IsActive:             true,
		Issuer:               ctx.Issuer(),
		Subject:              token.Subject,
		Type:                 token.Type,
		Scopes:               token.Scopes,
		AuthorizationDetails: token.AuthDetails,
		ClientID:             token.ClientID,
		IssuedAtTimestamp:    token.CreatedAtTimestamp,
		NotBeforeTimestamp:   token.CreatedAtTimestamp,
		ExpiresAtTimestamp:   token.ExpiresAtTimestamp,
		Confirmation:         cnf,
		ResourceAudiences:    token.Resources,
	}, nil
}
