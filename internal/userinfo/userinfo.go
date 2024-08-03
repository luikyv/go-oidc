package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleUserInfoRequest(ctx *utils.Context) (userInfoResponse, goidc.OAuthError) {

	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return userInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	tokenID, oauthErr := token.TokenID(ctx, accessToken)
	if oauthErr != nil {
		return userInfoResponse{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return userInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, accessToken, tokenType); err != nil {
		return userInfoResponse{}, err
	}

	client, err := ctx.Client(grantSession.ClientID)
	if err != nil {
		return userInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	resp, oauthErr := getUserInfoResponse(ctx, client, grantSession)
	if oauthErr != nil {
		return userInfoResponse{}, oauthErr
	}

	return resp, nil
}

func getUserInfoResponse(
	ctx *utils.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) (
	userInfoResponse,
	goidc.OAuthError,
) {

	userInfoClaims := map[string]any{
		goidc.ClaimSubject: grantSession.Subject,
	}
	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	resp := userInfoResponse{}
	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if client.UserInfoSignatureAlgorithm == "" {
		resp.Claims = userInfoClaims
		return resp, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Host
	userInfoClaims[goidc.ClaimAudience] = client.ID
	jwtUserInfoClaims, err := signUserInfoClaims(ctx, client, userInfoClaims)
	if err != nil {
		return userInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if client.UserInfoKeyEncryptionAlgorithm == "" {
		resp.JWTClaims = jwtUserInfoClaims
		return resp, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return userInfoResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	resp.JWTClaims = jwtUserInfoClaims
	return resp, nil
}

func signUserInfoClaims(
	ctx *utils.Context,
	client *goidc.Client,
	claims map[string]any,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.UserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.Algorithm)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
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
	ctx *utils.Context,
	client *goidc.Client,
	userInfoJWT string,
) (
	string,
	goidc.OAuthError,
) {
	jwk, oauthErr := client.UserInfoEncryptionJWK()
	if oauthErr != nil {
		return "", oauthErr
	}

	encryptedUserInfoJWT, oauthErr := token.EncryptJWT(ctx, userInfoJWT, jwk, client.UserInfoContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedUserInfoJWT, nil
}
