package oauth

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func IntrospectToken(
	ctx utils.Context,
	req models.TokenIntrospectionRequest,
) (
	models.TokenIntrospectionInfo,
	models.OAuthError,
) {
	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientId))
		return models.TokenIntrospectionInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return models.TokenIntrospectionInfo{}, err
	}

	resp := getTokenIntrospectionInfo(ctx, req.Token)
	if !resp.IsActive && resp.ClientId != client.Id {
		return models.TokenIntrospectionInfo{}, models.NewOAuthError(goidc.InvalidClient, "invalid token")
	}

	return models.TokenIntrospectionInfo{}, nil
}

func validateTokenIntrospectionRequest(
	_ utils.Context,
	req models.TokenIntrospectionRequest,
	client models.Client,
) models.OAuthError {
	if !client.IsGrantTypeAllowed(goidc.IntrospectionGrant) {
		return models.NewOAuthError(goidc.InvalidGrant, "client not allowed to introspect tokens")
	}

	if req.Token == "" {
		return models.NewOAuthError(goidc.InvalidRequest, "token is required")
	}

	return nil
}

func getTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) models.TokenIntrospectionInfo {

	if len(token) == goidc.RefreshTokenLength {
		return getRefreshTokenIntrospectionInfo(ctx, token)
	}

	if unit.IsJws(token) {
		return getJwtTokenIntrospectionInfo(ctx, token)
	}

	return getOpaqueTokenIntrospectionInfo(ctx, token)
}

func getRefreshTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) models.TokenIntrospectionInfo {
	grantSession, err := ctx.GrantSessionManager.GetByRefreshToken(token)
	if err != nil {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.IsRefreshSessionExpired() {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return models.TokenIntrospectionInfo{
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
) models.TokenIntrospectionInfo {
	// TODO: Get the grant session instead.
	claims, err := utils.GetValidTokenClaims(ctx, token)
	if err != nil {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return models.TokenIntrospectionInfo{
		IsActive:              true,
		AdditionalTokenClaims: claims,
	}
}

func getOpaqueTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) models.TokenIntrospectionInfo {
	grantSession, err := ctx.GrantSessionManager.GetByTokenId(token)
	if err != nil {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	if grantSession.HasLastTokenExpired() {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	return models.TokenIntrospectionInfo{
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
