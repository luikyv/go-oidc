package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func userInfo(ctx *oidc.Context) (response, error) {

	accessToken, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return response{}, oidcerr.New(oidcerr.CodeInvalidToken, "no token found")
	}

	tokenID, oauthErr := token.ExtractID(ctx, accessToken)
	if oauthErr != nil {
		return response{}, oauthErr
	}

	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid token")
	}

	if err := validateUserInfoRequest(ctx, grantSession, accessToken, tokenType); err != nil {
		return response{}, err
	}

	client, err := ctx.Client(grantSession.ClientID)
	if err != nil {
		return response{}, oidcerr.New(oidcerr.CodeInternalError, err.Error())
	}

	resp, oauthErr := userInfoResponse(ctx, client, grantSession)
	if oauthErr != nil {
		return response{}, oauthErr
	}

	return resp, nil
}

func userInfoResponse(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) (
	response,
	error,
) {

	userInfoClaims := map[string]any{
		goidc.ClaimSubject: grantSession.Subject,
	}
	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	resp := response{}
	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if client.UserInfoSignatureAlgorithm == "" {
		resp.claims = userInfoClaims
		return resp, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Host
	userInfoClaims[goidc.ClaimAudience] = client.ID
	jwtUserInfoClaims, err := signUserInfoClaims(ctx, client, userInfoClaims)
	if err != nil {
		return response{}, oidcerr.New(oidcerr.CodeInternalError, err.Error())
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if client.UserInfoKeyEncryptionAlgorithm == "" {
		resp.jwtClaims = jwtUserInfoClaims
		return resp, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return response{}, oidcerr.New(oidcerr.CodeInternalError, err.Error())
	}
	resp.jwtClaims = jwtUserInfoClaims
	return resp, nil
}

func signUserInfoClaims(
	ctx *oidc.Context,
	client *goidc.Client,
	claims map[string]any,
) (
	string,
	error,
) {
	privateJWK := ctx.UserInfoSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.Algorithm)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInternalError, err.Error())
	}

	return idToken, nil
}

func encryptUserInfoJWT(
	ctx *oidc.Context,
	client *goidc.Client,
	userInfoJWT string,
) (
	string,
	error,
) {
	jwk, err := client.UserInfoEncryptionJWK()
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInvalidRequest, err.Error())
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
) error {
	if grantSession.HasLastTokenExpired() {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "token expired")
	}

	if !strutil.ContainsOpenID(grantSession.ActiveScopes) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid scope")
	}

	confirmation := goidc.TokenConfirmation{
		JWKThumbprint:               grantSession.JWKThumbprint,
		ClientCertificateThumbprint: grantSession.ClientCertThumbprint,
	}
	return token.ValidatePoP(ctx, accessToken, tokenType, confirmation)
}
