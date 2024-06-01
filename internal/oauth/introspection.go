package oauth

import (
	"log/slog"
	"slices"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func IntrospectToken(
	ctx utils.Context,
	req models.TokenIntrospectionRequest,
) (
	models.TokenIntrospectionInfo,
	models.OAuthError,
) {
	client, err := token.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return models.TokenIntrospectionInfo{}, err
	}

	if err := validateTokenIntrospectionRequest(ctx, req, client); err != nil {
		return models.TokenIntrospectionInfo{}, err
	}

	resp := getTokenIntrospectionInfo(ctx, req.Token)
	if !resp.IsActive && resp.ClientId != client.Id {
		return models.TokenIntrospectionInfo{}, models.NewOAuthError(constants.InvalidClient, "invalid token")
	}

	return models.TokenIntrospectionInfo{}, nil
}

func validateTokenIntrospectionRequest(
	_ utils.Context,
	req models.TokenIntrospectionRequest,
	client models.Client,
) models.OAuthError {
	if !client.IsGrantTypeAllowed(constants.IntrospectionGrant) {
		return models.NewOAuthError(constants.InvalidGrant, "client not allowed to introspect tokens")
	}

	if req.Token == "" {
		return models.NewOAuthError(constants.InvalidRequest, "token is required")
	}

	return nil
}

func getTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) models.TokenIntrospectionInfo {

	if len(token) == constants.RefreshTokenLength {
		return getRefreshTokenIntrospectionInfo(ctx, token)
	}

	if unit.IsJwt(token) {
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
		IsActive:           true,
		Scopes:             grantSession.GrantedScopes,
		ClientId:           grantSession.ClientId,
		Username:           grantSession.Subject,
		ExpiresAtTimestamp: grantSession.ExpiresAtTimestamp,
		AdditionalClaims:   grantSession.AdditionalTokenClaims,
	}
}

func getJwtTokenIntrospectionInfo(
	ctx utils.Context,
	token string,
) models.TokenIntrospectionInfo {
	claims, err := utils.GetValidTokenClaims(ctx, token)
	if err != nil {
		return models.TokenIntrospectionInfo{
			IsActive: false,
		}
	}

	additionalClaims := map[string]any{}
	for k, v := range claims {
		if !slices.Contains(constants.Claims, constants.Claim(k)) {
			additionalClaims[k] = v
		}
	}
	return models.TokenIntrospectionInfo{
		IsActive:           true,
		Scopes:             claims[string(constants.ScopeClaim)].(string),
		ClientId:           claims[string(constants.AudienceClaim)].(string),
		Username:           claims[string(constants.AudienceClaim)].(string),
		ExpiresAtTimestamp: claims[string(constants.AudienceClaim)].(int),
		AdditionalClaims:   additionalClaims,
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
		IsActive:           true,
		Scopes:             grantSession.ActiveScopes,
		ClientId:           grantSession.ClientId,
		Username:           grantSession.Subject,
		ExpiresAtTimestamp: grantSession.LastTokenIssuedAtTimestamp + grantSession.TokenExpiresInSecs,
		AdditionalClaims:   grantSession.AdditionalTokenClaims,
	}
}
