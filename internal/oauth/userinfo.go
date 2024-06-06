package oauth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleUserInfoRequest(ctx utils.Context) (models.UserInfoResponse, models.OAuthError) {

	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return models.UserInfoResponse{}, models.NewOAuthError(constants.AccessDenied, "no token found")
	}

	tokenId, oauthErr := utils.GetTokenId(ctx, token)
	if oauthErr != nil {
		return models.UserInfoResponse{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionManager.GetByTokenId(tokenId)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(constants.InvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, token, tokenType); err != nil {
		return models.UserInfoResponse{}, err
	}

	client, err := ctx.GetClient(grantSession.ClientId)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return getUserInfoResponse(ctx, client, grantSession), nil
}

func validateUserInfoRequest(
	ctx utils.Context,
	grantSession models.GrantSession,
	token string,
	tokenType constants.TokenType,
) models.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return models.NewOAuthError(constants.InvalidRequest, "token expired")
	}

	if !unit.ScopesContainsOpenId(grantSession.GrantedScopes) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid scope")
	}

	if err := utils.ValidateDpop(ctx, token, tokenType, grantSession); err != nil {
		return err
	}

	return utils.ValidateTlsProofOfPossesion(ctx, grantSession)
}

func getUserInfoResponse(
	ctx utils.Context,
	client models.Client,
	grantSession models.GrantSession,
) models.UserInfoResponse {

	userInfoClaims := map[string]any{
		string(constants.SubjectClaim): grantSession.Subject,
	}
	for k, v := range grantSession.AdditionalIdTokenClaims {
		userInfoClaims[k] = v
	}

	userInfoResponse := models.UserInfoResponse{}
	if client.UserInfoSignatureAlgorithm != "" {
		userInfoClaims[string(constants.IssuerClaim)] = ctx.Host
		userInfoClaims[string(constants.AudienceClaim)] = grantSession.ClientId
		userInfoResponse.SignedClaims = signUserInfoClaims(ctx, client, userInfoClaims)
	} else {
		userInfoResponse.Claims = userInfoClaims
	}

	return userInfoResponse
}

func signUserInfoClaims(ctx utils.Context, client models.Client, claims map[string]any) string {
	privateJwk := ctx.GetUserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.Algorithm)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return idToken
}
