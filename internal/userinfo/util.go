package userinfo

import (
	"fmt"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleUserInfoRequest(ctx oidc.Context) (response, error) {

	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	tokenID, err := token.ExtractID(ctx, accessToken)
	if err != nil {
		return response{}, err
	}

	grantSession, err := ctx.GrantSessionByTokenID(tokenID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"invalid token", err)
	}

	if err := validateRequest(ctx, grantSession, accessToken); err != nil {
		return response{}, err
	}

	client, err := ctx.Client(grantSession.ClientID)
	if err != nil {
		return response{}, err
	}

	resp, err := userInfoResponse(ctx, client, grantSession)
	if err != nil {
		return response{}, err
	}

	return resp, nil
}

func userInfoResponse(
	ctx oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) (
	response,
	error,
) {
	sub := ctx.ExportableSubject(grantSession.Subject, client)
	userInfoClaims := map[string]any{
		goidc.ClaimSubject: sub,
	}
	for k, v := range grantSession.AdditionalUserInfoClaims {
		userInfoClaims[k] = v
	}

	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if client.UserInfoSigAlg == "" {
		return response{
			claims: userInfoClaims,
		}, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Host
	userInfoClaims[goidc.ClaimAudience] = client.ID

	jwtUserInfoClaims, err := signUserInfoClaims(ctx, client, userInfoClaims)
	if err != nil {
		return response{}, err
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if !ctx.UserInfoEncIsEnabled || client.UserInfoKeyEncAlg == "" {
		return response{
			jwtClaims: jwtUserInfoClaims,
		}, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, client, jwtUserInfoClaims)
	if err != nil {
		return response{}, err
	}
	return response{
		jwtClaims: jwtUserInfoClaims,
	}, nil
}

func signUserInfoClaims(
	ctx oidc.Context,
	client *goidc.Client,
	claims map[string]any,
) (
	string,
	error,
) {

	if ctx.UserInfoSigAlgsContainsNone() && client.UserInfoSigAlg == goidc.None {
		return joseutil.Unsigned(claims), nil
	}

	alg := ctx.UserInfoDefaultSigAlg
	if client.UserInfoSigAlg != "" {
		alg = client.UserInfoSigAlg
	}

	jws, err := joseutil.Sign(ctx, claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the user info claims: %w", err)
	}

	return jws, nil
}

func encryptUserInfoJWT(
	ctx oidc.Context,
	c *goidc.Client,
	userInfoJWT string,
) (
	string,
	error,
) {
	jwk, err := clientutil.JWKByAlg(ctx, c, string(c.UserInfoKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not find a jwk to encrypt the user info response", err)
	}

	contentEncAlg := c.UserInfoContentEncAlg
	if contentEncAlg == "" {
		contentEncAlg = ctx.UserInfoDefaultContentEncAlg
	}
	userInfoJWE, err := joseutil.Encrypt(userInfoJWT, jwk, contentEncAlg)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the user info response: %w", err)
	}

	return userInfoJWE, nil
}

func validateRequest(
	ctx oidc.Context,
	grantSession *goidc.GrantSession,
	accessToken string,
) error {
	if grantSession.HasLastTokenExpired() {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "token expired")
	}

	if !strutil.ContainsOpenID(grantSession.ActiveScopes) {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid scope")
	}

	confirmation := goidc.TokenConfirmation{
		JWKThumbprint:        grantSession.JWKThumbprint,
		ClientCertThumbprint: grantSession.ClientCertThumbprint,
	}
	if err := token.ValidatePoP(ctx, accessToken, confirmation); err != nil {
		return err
	}

	return nil
}
