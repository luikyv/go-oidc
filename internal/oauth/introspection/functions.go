package introspection

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateTokenIntrospectionRequest(
	_ utils.Context,
	req utils.TokenIntrospectionRequest,
	client goidc.Client,
) goidc.OAuthError {
	if !client.IsGrantTypeAllowed(goidc.IntrospectionGrant) {
		return goidc.NewOAuthError(goidc.InvalidGrant, "client not allowed to introspect tokens")
	}

	if req.Token == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "token is required")
	}

	return nil
}

func getTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) utils.TokenIntrospectionInfo {

	if len(token) == goidc.RefreshTokenLength {
		return getRefreshTokenIntrospectionInfo(ctx, token)
	}

	if utils.IsJws(token) {
		return getJwtTokenIntrospectionInfo(ctx, token)
	}

	return getOpaqueTokenIntrospectionInfo(ctx, token)
}

func getRefreshTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	grantSession, err := ctx.GetGrantSessionByRefreshToken(token)
	if err != nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.IsRefreshSessionExpired() {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return utils.TokenIntrospectionInfo{
		IsActive:                    true,
		Scopes:                      grantSession.GrantedScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientId:                    grantSession.ClientId,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.ExpiresAtTimestamp,
		JwkThumbprint:               grantSession.JwkThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}

func getJwtTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	// TODO: Get the grant session instead.
	claims, err := utils.GetValidTokenClaims(ctx, token)
	if err != nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return utils.TokenIntrospectionInfo{
		IsActive:              true,
		AdditionalTokenClaims: claims,
	}
}

func getOpaqueTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) utils.TokenIntrospectionInfo {
	grantSession, err := ctx.GetGrantSessionByTokenId(token)
	if err != nil {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.HasLastTokenExpired() {
		return utils.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return utils.TokenIntrospectionInfo{
		IsActive:                    true,
		Scopes:                      grantSession.ActiveScopes,
		AuthorizationDetails:        grantSession.GrantedAuthorizationDetails,
		ClientId:                    grantSession.ClientId,
		Subject:                     grantSession.Subject,
		ExpiresAtTimestamp:          grantSession.LastTokenIssuedAtTimestamp + grantSession.TokenExpiresInSecs,
		JwkThumbprint:               grantSession.JwkThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
		AdditionalTokenClaims:       grantSession.AdditionalTokenClaims,
	}
}
