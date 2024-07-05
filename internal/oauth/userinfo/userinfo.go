package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func HandleUserInfoRequest(ctx utils.Context) (utils.UserInfoResponse, goidc.OAuthError) {

	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return utils.UserInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	tokenID, oauthErr := utils.GetTokenID(ctx, token)
	if oauthErr != nil {
		return utils.UserInfoResponse{}, oauthErr
	}

	grantSession, err := ctx.GetGrantSessionByTokenID(tokenID)
	if err != nil {
		return utils.UserInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, token, tokenType); err != nil {
		return utils.UserInfoResponse{}, err
	}

	client, err := ctx.GetClient(grantSession.ClientID)
	if err != nil {
		return utils.UserInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	userInfoResponse, oauthErr := getUserInfoResponse(ctx, client, grantSession)
	if oauthErr != nil {
		return utils.UserInfoResponse{}, oauthErr
	}

	return userInfoResponse, nil
}

func getUserInfoResponse(
	ctx utils.Context,
	client goidc.Client,
	grantSession goidc.GrantSession,
) (
	utils.UserInfoResponse,
	goidc.OAuthError,
) {

	userInfoClaims := map[string]any{
		goidc.ClaimSubject: grantSession.Subject,
	}
	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	userInfoResponse := utils.UserInfoResponse{}
	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if client.UserInfoSignatureAlgorithm == "" {
		userInfoResponse.Claims = userInfoClaims
		return userInfoResponse, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Host
	userInfoClaims[goidc.ClaimAudience] = client.ID
	jwtUserInfoClaims, err := signUserInfoClaims(ctx, client, userInfoClaims)
	if err != nil {
		return utils.UserInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if client.UserInfoKeyEncryptionAlgorithm == "" {
		userInfoResponse.JWTClaims = jwtUserInfoClaims
		return userInfoResponse, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return utils.UserInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	userInfoResponse.JWTClaims = jwtUserInfoClaims
	return userInfoResponse, nil
}

func signUserInfoClaims(
	ctx utils.Context,
	client goidc.Client,
	claims map[string]any,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.GetUserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.GetAlgorithm())
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.GetKeyID()),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return idToken, nil
}

func encryptUserInfoJWT(
	ctx utils.Context,
	client goidc.Client,
	userInfoJWT string,
) (
	string,
	goidc.OAuthError,
) {
	jwk, oauthErr := client.GetUserInfoEncryptionJWK()
	if oauthErr != nil {
		return "", oauthErr
	}

	encryptedUserInfoJWT, oauthErr := utils.EncryptJWT(ctx, userInfoJWT, jwk, client.UserInfoContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedUserInfoJWT, nil
}
