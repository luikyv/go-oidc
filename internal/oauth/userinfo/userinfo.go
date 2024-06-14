package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleUserInfoRequest(ctx utils.Context) (models.UserInfoResponse, models.OAuthError) {

	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return models.UserInfoResponse{}, models.NewOAuthError(constants.InvalidToken, "no token found")
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

func getUserInfoResponse(
	ctx utils.Context,
	client models.Client,
	grantSession models.GrantSession,
) models.UserInfoResponse {

	userInfoClaims := map[string]any{
		constants.SubjectClaim: grantSession.Subject,
	}

	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	userInfoResponse := models.UserInfoResponse{}
	if client.UserInfoSignatureAlgorithm != "" {
		userInfoClaims[constants.IssuerClaim] = ctx.Host
		userInfoClaims[constants.AudienceClaim] = grantSession.ClientId
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
