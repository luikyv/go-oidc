package token

import (
	"errors"
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(
	ctx oidc.Context,
	req queryRequest,
) (
	goidc.TokenInfo,
	error,
) {
	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateIntrospectionRequest(ctx, req, c); err != nil {
		return goidc.TokenInfo{}, err
	}

	// The information of an invalid token must not be sent as an error.
	// It will be returned as the default value of [goidc.TokenInfo] with the
	// field is_active as false.
	tokenInfo, _ := IntrospectionInfo(ctx, req.token)
	return tokenInfo, nil
}

func validateIntrospectionRequest(
	_ oidc.Context,
	req queryRequest,
	c *goidc.Client,
) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantIntrospection) {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"client not allowed to introspect tokens")
	}

	if req.token == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token is required")
	}

	return nil
}

func IntrospectionInfo(
	ctx oidc.Context,
	accessToken string,
) (
	goidc.TokenInfo,
	error,
) {

	if len(accessToken) == goidc.RefreshTokenLength {
		return refreshTokenInfo(ctx, accessToken)
	}

	if jwtutil.IsJWS(accessToken) {
		return jwtTokenInfo(ctx, accessToken)
	}

	return opaqueTokenInfo(ctx, accessToken)
}

func refreshTokenInfo(
	ctx oidc.Context,
	token string,
) (
	goidc.TokenInfo,
	error,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(token)
	if err != nil {
		return goidc.TokenInfo{},
			errors.New("token not found")
	}

	if grantSession.IsExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" ||
		grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:               grantSession.JWKThumbprint,
			ClientCertificateThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Type:                  goidc.TokenHintRefresh,
		Scopes:                grantSession.GrantedScopes,
		AuthorizationDetails:  grantSession.GrantedAuthorizationDetails,
		ClientID:              grantSession.ClientID,
		Subject:               grantSession.Subject,
		ExpiresAtTimestamp:    grantSession.ExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.GrantedResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}

func jwtTokenInfo(
	ctx oidc.Context,
	accessToken string,
) (
	goidc.TokenInfo,
	error,
) {
	claims, err := validClaims(ctx, accessToken)
	if err != nil || claims[goidc.ClaimTokenID] == nil {
		return goidc.TokenInfo{}, errors.New("invalid token")
	}

	return tokenIntrospectionInfoByID(ctx, claims[goidc.ClaimTokenID].(string))
}

func opaqueTokenInfo(
	ctx oidc.Context,
	token string,
) (goidc.TokenInfo, error) {
	return tokenIntrospectionInfoByID(ctx, token)
}

func tokenIntrospectionInfoByID(
	ctx oidc.Context,
	tokenID string,
) (
	goidc.TokenInfo,
	error,
) {
	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return goidc.TokenInfo{}, errors.New("token not found")
	}

	if grantSession.HasLastTokenExpired() {
		return goidc.TokenInfo{}, errors.New("token is expired")
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:               grantSession.JWKThumbprint,
			ClientCertificateThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		GrantID:               grantSession.ID,
		IsActive:              true,
		Type:                  goidc.TokenHintAccess,
		Scopes:                grantSession.ActiveScopes,
		AuthorizationDetails:  grantSession.GrantedAuthorizationDetails,
		ClientID:              grantSession.ClientID,
		Subject:               grantSession.Subject,
		ExpiresAtTimestamp:    grantSession.LastTokenExpiresAtTimestamp,
		Confirmation:          cnf,
		ResourceAudiences:     grantSession.ActiveResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}, nil
}
