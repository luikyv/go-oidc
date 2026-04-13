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
	if grant.JWKThumbprint != "" || grant.CertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:  grant.JWKThumbprint,
			CertThumbprint: grant.CertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:            grant.ID,
		IsActive:           true,
		Issuer:             ctx.Issuer(),
		Subject:            grant.Subject,
		Type:               goidc.TokenTypeBearer,
		Scopes:             grant.Scopes,
		AuthDetails:        grant.AuthDetails,
		ClientID:           grant.ClientID,
		IssuedAtTimestamp:  grant.CreatedAtTimestamp,
		NotBeforeTimestamp: grant.CreatedAtTimestamp,
		ExpiresAtTimestamp: grant.ExpiresAtTimestamp,
		Confirmation:       cnf,
		ResourceAudiences:  grant.Resources,
	}, nil
}

func accessTokenInfo(ctx oidc.Context, accessToken string) (goidc.TokenInfo, error) {
	id, err := ExtractID(ctx, accessToken)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	tkn, err := ctx.TokenByID(id)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("error fetching token: %w", err)
	}

	if tkn.IsExpired() {
		return goidc.TokenInfo{IsActive: false}, nil
	}

	grant, err := ctx.GrantByID(tkn.GrantID)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("error fetching grant: %w", err)
	}

	if grant.IsExpired() {
		return goidc.TokenInfo{IsActive: false}, nil
	}

	var cnf *goidc.TokenConfirmation
	if tkn.JWKThumbprint != "" || tkn.CertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:  tkn.JWKThumbprint,
			CertThumbprint: tkn.CertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:            tkn.GrantID,
		IsActive:           true,
		Issuer:             ctx.Issuer(),
		Subject:            tkn.Subject,
		Type:               tkn.Type,
		Scopes:             tkn.Scopes,
		AuthDetails:        tkn.AuthDetails,
		ClientID:           tkn.ClientID,
		IssuedAtTimestamp:  tkn.CreatedAtTimestamp,
		NotBeforeTimestamp: tkn.CreatedAtTimestamp,
		ExpiresAtTimestamp: tkn.ExpiresAtTimestamp,
		Confirmation:       cnf,
		ResourceAudiences:  tkn.Resources,
		AdditionalClaims:   ctx.TokenClaims(tkn, grant),
	}, nil
}
