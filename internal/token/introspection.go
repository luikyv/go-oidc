package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(
	ctx *oidc.Context,
	req introspectionRequest,
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

	return IntrospectionInfo(ctx, req.token), nil
}

func validateIntrospectionRequest(
	_ *oidc.Context,
	req introspectionRequest,
	c *goidc.Client,
) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantIntrospection) {
		return oidcerr.New(oidcerr.CodeInvalidGrant,
			"client not allowed to introspect tokens")
	}

	if req.token == "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "token is required")
	}

	return nil
}

func IntrospectionInfo(
	ctx *oidc.Context,
	accessToken string,
) goidc.TokenInfo {

	if len(accessToken) == goidc.RefreshTokenLength {
		return refreshTokenInfo(ctx, accessToken)
	}

	if jwtutil.IsJWS(accessToken) {
		return jwtTokenInfo(ctx, accessToken)
	}

	return opaqueTokenInfo(ctx, accessToken)
}

func refreshTokenInfo(
	ctx *oidc.Context,
	token string,
) goidc.TokenInfo {
	grantSession, err := ctx.GrantSessionByRefreshToken(token)
	if err != nil {
		return goidc.TokenInfo{
			IsActive: false,
		}
	}

	if grantSession.IsExpired() {
		return goidc.TokenInfo{
			IsActive: false,
		}
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
		IsActive:              true,
		Type:                  goidc.TokenHintRefresh,
		Scopes:                grantSession.GrantedScopes,
		AuthorizationDetails:  grantSession.GrantedAuthorizationDetails,
		ClientID:              grantSession.ClientID,
		Subject:               grantSession.Subject,
		ExpiresAtTimestamp:    grantSession.ExpiresAtTimestamp,
		Confirmation:          cnf,
		Resources:             grantSession.GrantedResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}
}

func jwtTokenInfo(
	ctx *oidc.Context,
	accessToken string,
) goidc.TokenInfo {
	claims, err := validClaims(ctx, accessToken)
	if err != nil || claims[goidc.ClaimTokenID] == nil {
		return goidc.TokenInfo{
			IsActive: false,
		}
	}

	return tokenIntrospectionInfoByID(ctx, claims[goidc.ClaimTokenID].(string))
}

func opaqueTokenInfo(
	ctx *oidc.Context,
	token string,
) goidc.TokenInfo {
	return tokenIntrospectionInfoByID(ctx, token)
}

func tokenIntrospectionInfoByID(
	ctx *oidc.Context,
	tokenID string,
) goidc.TokenInfo {
	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return goidc.TokenInfo{
			IsActive: false,
		}
	}

	if grantSession.HasLastTokenExpired() {
		return goidc.TokenInfo{
			IsActive: false,
		}
	}

	var cnf *goidc.TokenConfirmation
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
		cnf = &goidc.TokenConfirmation{
			JWKThumbprint:               grantSession.JWKThumbprint,
			ClientCertificateThumbprint: grantSession.ClientCertThumbprint,
		}
	}

	return goidc.TokenInfo{
		IsActive:              true,
		Type:                  goidc.TokenHintAccess,
		Scopes:                grantSession.ActiveScopes,
		AuthorizationDetails:  grantSession.GrantedAuthorizationDetails,
		ClientID:              grantSession.ClientID,
		Subject:               grantSession.Subject,
		ExpiresAtTimestamp:    grantSession.LastTokenExpiresAtTimestamp,
		Confirmation:          cnf,
		Resources:             grantSession.ActiveResources,
		AdditionalTokenClaims: grantSession.AdditionalTokenClaims,
	}
}
