package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleUserInfoRequest(ctx *oidc.Context) (userInfoResponse, oidc.Error) {

	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return userInfoResponse{}, oidc.NewError(oidc.ErrorCodeInvalidToken, "no token found")
	}

	tokenID, oauthErr := token.TokenID(ctx, accessToken)
	if oauthErr != nil {
		return userInfoResponse{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return userInfoResponse{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, accessToken, tokenType); err != nil {
		return userInfoResponse{}, err
	}

	client, err := ctx.Client(grantSession.ClientID)
	if err != nil {
		return userInfoResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	resp, oauthErr := getUserInfoResponse(ctx, client, grantSession)
	if oauthErr != nil {
		return userInfoResponse{}, oauthErr
	}

	return resp, nil
}

func getUserInfoResponse(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) (
	userInfoResponse,
	oidc.Error,
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
		return userInfoResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if client.UserInfoKeyEncryptionAlgorithm == "" {
		resp.JWTClaims = jwtUserInfoClaims
		return resp, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return userInfoResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	resp.JWTClaims = jwtUserInfoClaims
	return resp, nil
}

func signUserInfoClaims(
	ctx *oidc.Context,
	client *goidc.Client,
	claims map[string]any,
) (
	string,
	oidc.Error,
) {
	privateJWK := ctx.UserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.Algorithm)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return idToken, nil
}

func encryptUserInfoJWT(
	ctx *oidc.Context,
	client *goidc.Client,
	userInfoJWT string,
) (
	string,
	oidc.Error,
) {
	jwk, err := client.UserInfoEncryptionJWK()
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInvalidRequest, err.Error())
	}

	encryptedUserInfoJWT, oauthErr := token.EncryptJWT(ctx, userInfoJWT, jwk, client.UserInfoContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedUserInfoJWT, nil
}

func validateUserInfoRequest(
	ctx *oidc.Context,
	grantSession *goidc.GrantSession,
	accessToken string,
	tokenType goidc.TokenType,
) oidc.Error {
	if grantSession.HasLastTokenExpired() {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "token expired")
	}

	if !strutil.ContainsOpenID(grantSession.ActiveScopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid scope")
	}

	confirmation := token.Confirmation{
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertificateThumbprint,
	}
	return token.ValidatePoP(ctx, accessToken, tokenType, confirmation)
}
