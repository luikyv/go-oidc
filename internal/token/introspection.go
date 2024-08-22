package token

import (
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(
	ctx *oidc.Context,
	req introspectionRequest,
) (
	goidc.TokenInfo,
	oidc.Error,
) {
	c, err := client.Authenticated(ctx, req.AuthnRequest)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateIntrospectionRequest(ctx, req, c); err != nil {
		return goidc.TokenInfo{}, err
	}

	return IntrospectionInfo(ctx, req.Token), nil
}

func validateIntrospectionRequest(
	_ *oidc.Context,
	req introspectionRequest,
	client *goidc.Client,
) oidc.Error {
	if !client.IsGrantTypeAllowed(goidc.GrantIntrospection) {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "client not allowed to introspect tokens")
	}

	if req.Token == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "token is required")
	}

	return nil
}

func IntrospectionInfo(
	ctx *oidc.Context,
	accessToken string,
) goidc.TokenInfo {

	if len(accessToken) == RefreshTokenLength {
		return refreshTokenInfo(ctx, accessToken)
	}

	if IsJWS(accessToken) {
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
	if grantSession.JWKThumbprint != "" || grantSession.ClientCertThumbprint != "" {
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
		AdditionalTokenClaims: grantSession.TokenOptions.AdditionalClaims,
	}
}

func jwtTokenInfo(
	ctx *oidc.Context,
	accessToken string,
) goidc.TokenInfo {
	claims, err := ValidClaims(ctx, accessToken)
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
		ExpiresAtTimestamp:    grantSession.LastTokenIssuedAtTimestamp + grantSession.TokenOptions.LifetimeSecs,
		Confirmation:          cnf,
		AdditionalTokenClaims: grantSession.TokenOptions.AdditionalClaims,
	}
}
