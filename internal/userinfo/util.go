package userinfo

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/jwtutil"
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

	tokenID, err := token.ExtractID(ctx, accessToken)
	if err != nil {
		return response{}, err
	}

	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"invalid token", err)
	}

	if err := validateRequest(ctx, grantSession, accessToken, tokenType); err != nil {
		return response{}, err
	}

	client, err := ctx.Client(grantSession.ClientID)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not load the client", err)
	}

	resp, err := userInfoResponse(ctx, client, grantSession)
	if err != nil {
		return response{}, err
	}

	return resp, nil
}

func userInfoResponse(
	ctx *oidc.Context,
	c *goidc.Client,
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
	if c.UserInfoSigAlg == "" {
		resp.claims = userInfoClaims
		return resp, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Host
	userInfoClaims[goidc.ClaimAudience] = c.ID
	jwtUserInfoClaims, err := signUserInfoClaims(ctx, c, userInfoClaims)
	if err != nil {
		return response{}, err
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if c.UserInfoKeyEncAlg == "" {
		resp.jwtClaims = jwtUserInfoClaims
		return resp, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, c, jwtUserInfoClaims)
	if err != nil {
		return response{}, err
	}
	resp.jwtClaims = jwtUserInfoClaims
	return resp, nil
}

func signUserInfoClaims(
	ctx *oidc.Context,
	c *goidc.Client,
	claims map[string]any,
) (
	string,
	error,
) {
	jwk := ctx.UserInfoSignatureKey(c)
	jws, err := jwtutil.Sign(claims, jwk,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID))
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not sign the user info claims", err)
	}

	return jws, nil
}

func encryptUserInfoJWT(
	_ *oidc.Context,
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

	userInfoJWE, err := jwtutil.Encrypt(userInfoJWT, jwk, client.UserInfoContentEncAlg)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not encrypt the user info response", err)
	}

	return userInfoJWE, nil
}

func validateRequest(
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
