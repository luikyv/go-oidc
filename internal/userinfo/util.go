package userinfo

import (
	"fmt"
	"maps"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
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

func userInfoResponse(ctx oidc.Context, c *goidc.Client, grantSession *goidc.GrantSession) (response, error) {
	sub := ctx.ExportableSubject(grantSession.Subject, c)
	userInfoClaims := map[string]any{
		goidc.ClaimSubject: sub,
	}
	maps.Copy(userInfoClaims, grantSession.AdditionalUserInfoClaims)

	// If the client doesn't require the user info to be signed,
	// we'll just return the claims as a JSON object.
	if c.UserInfoSigAlg == "" {
		return response{
			claims: userInfoClaims,
		}, nil
	}

	userInfoClaims[goidc.ClaimIssuer] = ctx.Issuer()
	userInfoClaims[goidc.ClaimAudience] = c.ID

	jwtUserInfoClaims, err := signUserInfoClaims(ctx, c, userInfoClaims)
	if err != nil {
		return response{}, err
	}

	// If the client doesn't require the user info to be encrypted,
	// we'll just return the claims as a signed JWT.
	if !ctx.UserInfoEncIsEnabled || c.UserInfoKeyEncAlg == "" {
		return response{
			jwtClaims: jwtUserInfoClaims,
		}, nil
	}

	jwtUserInfoClaims, err = encryptUserInfoJWT(ctx, c, jwtUserInfoClaims)
	if err != nil {
		return response{}, err
	}
	return response{
		jwtClaims: jwtUserInfoClaims,
	}, nil
}

func signUserInfoClaims(ctx oidc.Context, c *goidc.Client, claims map[string]any) (string, error) {

	if slices.Contains(ctx.UserInfoSigAlgs, goidc.None) && c.UserInfoSigAlg == goidc.None {
		return joseutil.Unsigned(claims), nil
	}

	alg := ctx.UserInfoDefaultSigAlg
	if c.UserInfoSigAlg != "" {
		alg = c.UserInfoSigAlg
	}

	jws, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the user info claims: %w", err)
	}

	return jws, nil
}

func encryptUserInfoJWT(ctx oidc.Context, c *goidc.Client, userInfoJWT string) (string, error) {
	jwk, err := client.JWKByAlg(ctx, c, string(c.UserInfoKeyEncAlg))
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

func validateRequest(ctx oidc.Context, gs *goidc.GrantSession, tkn string) error {
	if gs.HasLastTokenExpired() {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "token expired")
	}

	if !strutil.ContainsOpenID(gs.ActiveScopes) {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid scope")
	}

	confirmation := goidc.TokenConfirmation{
		JWKThumbprint:        gs.JWKThumbprint,
		ClientCertThumbprint: gs.ClientCertThumbprint,
	}
	if err := token.ValidatePoP(ctx, tkn, confirmation); err != nil {
		return err
	}

	return nil
}
