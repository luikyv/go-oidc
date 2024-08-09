package token

import (
	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func introspect(
	ctx *oidc.Context,
	req tokenIntrospectionRequest,
) (
	goidc.TokenInfo,
	oidc.Error,
) {
	client, err := authn.Client(ctx, req.ClientAuthnRequest)
	if err != nil {
		return goidc.TokenInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return goidc.TokenInfo{}, err
	}

	return TokenIntrospectionInfo(ctx, req.Token), nil
}

func validateTokenIntrospectionRequest(
	_ *oidc.Context,
	req tokenIntrospectionRequest,
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

func TokenIntrospectionInfo(
	ctx *oidc.Context,
	accessToken string,
) goidc.TokenInfo {

	if len(accessToken) == RefreshTokenLength {
		return getRefreshTokenIntrospectionInfo(ctx, accessToken)
	}

	if IsJWS(accessToken) {
		return getJWTTokenIntrospectionInfo(ctx, accessToken)
	}

	return opaqueTokenIntrospectionInfo(ctx, accessToken)
}

func getRefreshTokenIntrospectionInfo(
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

	return goidc.TokenInfo{
		IsActive:                    true,
		TokenUsage:                  goidc.TokenHintRefresh,
		Scopes:                      grantSession.GrantedScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientID:                    grantSession.ClientID,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.ExpiresAtTimestamp,
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}

func getJWTTokenIntrospectionInfo(
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

func opaqueTokenIntrospectionInfo(
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

	return goidc.TokenInfo{
		IsActive:                    true,
		TokenUsage:                  goidc.TokenHintAccess,
		Scopes:                      grantSession.ActiveScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientID:                    grantSession.ClientID,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.LastTokenIssuedAtTimestamp + grantSession.TokenLifetimeSecs,
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}
