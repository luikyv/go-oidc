package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func HandleUserInfoRequest(ctx utils.Context) (models.UserInfoResponse, models.OAuthError) {

	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return models.UserInfoResponse{}, models.NewOAuthError(goidc.InvalidToken, "no token found")
	}

	tokenId, oauthErr := utils.GetTokenId(ctx, token)
	if oauthErr != nil {
		return models.UserInfoResponse{}, oauthErr
	}

	grantSession, err := ctx.GetGrantSessionByTokenId(tokenId)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(goidc.InvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, token, tokenType); err != nil {
		return models.UserInfoResponse{}, err
	}

	client, err := ctx.GetClient(grantSession.ClientId)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(goidc.InternalError, err.Error())
	}

	userInfoResponse, oauthErr := getUserInfoResponse(ctx, client, grantSession)
	if oauthErr != nil {
		return models.UserInfoResponse{}, oauthErr
	}

	return userInfoResponse, nil
}

func getUserInfoResponse(
	ctx utils.Context,
	client models.Client,
	grantSession models.GrantSession,
) (
	models.UserInfoResponse,
	models.OAuthError,
) {

	userInfoClaims := map[string]any{
		goidc.SubjectClaim: grantSession.Subject,
	}
	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	userInfoResponse := models.UserInfoResponse{}
	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if client.UserInfoSignatureAlgorithm == "" {
		userInfoResponse.Claims = userInfoClaims
		return userInfoResponse, nil
	}

	userInfoClaims[goidc.IssuerClaim] = ctx.Host
	userInfoClaims[goidc.AudienceClaim] = client.Id
	jwtUserInfoClaims, err := signUserInfoClaims(ctx, client, userInfoClaims)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(goidc.InternalError, err.Error())
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if client.UserInfoKeyEncryptionAlgorithm == "" {
		userInfoResponse.JwtClaims = jwtUserInfoClaims
		return userInfoResponse, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJwt(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return models.UserInfoResponse{}, models.NewOAuthError(goidc.InternalError, err.Error())
	}
	userInfoResponse.JwtClaims = jwtUserInfoClaims
	return userInfoResponse, nil
}

func signUserInfoClaims(
	ctx utils.Context,
	client models.Client,
	claims map[string]any,
) (
	string,
	models.OAuthError,
) {
	privateJwk := ctx.GetUserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.Algorithm)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	if err != nil {
		return "", models.NewOAuthError(goidc.InternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return idToken, nil
}

func encryptUserInfoJwt(
	ctx utils.Context,
	client models.Client,
	userInfoJwt string,
) (
	string,
	models.OAuthError,
) {
	jwk, oauthErr := client.GetUserInfoEncryptionJwk()
	if oauthErr != nil {
		return "", oauthErr
	}

	encryptedUserInfoJwt, oauthErr := utils.EncryptJwt(ctx, userInfoJwt, jwk, client.UserInfoContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedUserInfoJwt, nil
}
