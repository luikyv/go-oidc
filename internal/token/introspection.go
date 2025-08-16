package token

import (
	"errors"
	"fmt"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(ctx oidc.Context, req queryRequest) (goidc.TokenInfo, error) {
	c, err := clientutil.Authenticated(ctx, clientutil.TokenIntrospectionAuthnContext)
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
		ctx.NotifyError(err)
	}

	if !ctx.IsClientAllowedTokenIntrospection(c, tokenInfo) {
		return goidc.TokenInfo{}, goidc.NewError(goidc.ErrorCodeAccessDenied,
			"client not allowed to introspect the token")
	}

	return tokenInfo, nil
}

func validateIntrospectionRequest(req queryRequest) error {
	if req.token == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token is missing")
	}
	return nil
}

func IntrospectionInfo(ctx oidc.Context, tkn string) (goidc.TokenInfo, error) {

	if joseutil.IsJWS(tkn) {
		return accessTokenInfo(ctx, tkn)
	}

	if len(tkn) == goidc.RefreshTokenLength {
		return refreshTokenInfo(ctx, tkn)
	}

	return accessTokenInfo(ctx, tkn)
}

func refreshTokenInfo(ctx oidc.Context, tkn string) (goidc.TokenInfo, error) {
	grantSession, err := ctx.GrantSessionByRefreshToken(tkn)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("token not found: %w", err)
	}

	if grantSession.IsExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        grantSession.JWKThumbprint,
			ClientCertThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Subject:               grantSession.Subject,
		Type:                  goidc.TokenHintRefresh,
		Scopes:                grantSession.GrantedScopes,
		AuthorizationDetails:  grantSession.GrantedAuthDetails,
		ClientID:              grantSession.ClientID,
		ExpiresAtTimestamp:    grantSession.ExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.GrantedResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}

func accessTokenInfo(ctx oidc.Context, accessToken string) (goidc.TokenInfo, error) {
	id, err := ExtractID(ctx, accessToken)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	grantSession, err := ctx.GrantSessionByTokenID(id)
	if err != nil {
		return goidc.TokenInfo{}, fmt.Errorf("token not found: %w", err)
	}

	if grantSession.HasLastTokenExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:        grantSession.JWKThumbprint,
			ClientCertThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Subject:               grantSession.Subject,
		Type:                  goidc.TokenHintAccess,
		Scopes:                grantSession.ActiveScopes,
		AuthorizationDetails:  grantSession.ActiveAuthDetails,
		ClientID:              grantSession.ClientID,
		ExpiresAtTimestamp:    grantSession.LastTokenExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.ActiveResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}
