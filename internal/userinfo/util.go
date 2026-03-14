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
	// TODO: Use the introspection endpoint to validate the token.
	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidToken, "no token found")
	}

	tokenID, err := token.ExtractID(ctx, accessToken)
	if err != nil {
		return response{}, err
	}

	tokenEntity, err := ctx.TokenByID(tokenID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid token", err)
	}

	if err := validateRequest(ctx, tokenEntity, accessToken); err != nil {
		return response{}, err
	}

	c, err := ctx.Client(tokenEntity.ClientID)
	if err != nil {
		return response{}, err
	}

	grant, err := ctx.GrantByID(tokenEntity.GrantID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "grant not found", err)
	}

	resp, err := userInfoResponse(ctx, c, tokenEntity, grant)
	if err != nil {
		return response{}, err
	}

	return resp, nil
}

func userInfoResponse(ctx oidc.Context, c *goidc.Client, t *goidc.Token, grant *goidc.Grant) (response, error) {
	sub := ctx.ExportableSubject(t.Subject, c)
	userInfoClaims := map[string]any{
		goidc.ClaimSubject: sub,
	}
	maps.Copy(userInfoClaims, ctx.UserInfoClaims(grant))

	// If the client doesn't require the user info to be signed, just return the claims as a JSON object.
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

	// If the client doesn't require the user info to be encrypted, just return the claims as a signed JWT.
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
	alg := ctx.UserInfoDefaultSigAlg
	if c.UserInfoSigAlg != "" && slices.Contains(ctx.UserInfoSigAlgs, c.UserInfoSigAlg) {
		alg = c.UserInfoSigAlg
	}

	if alg == goidc.None {
		return joseutil.Unsigned(claims), nil
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

	contentEncAlg := ctx.UserInfoDefaultContentEncAlg
	if c.UserInfoContentEncAlg != "" && slices.Contains(ctx.UserInfoContentEncAlgs, c.UserInfoContentEncAlg) {
		contentEncAlg = c.UserInfoContentEncAlg
	}

	userInfoJWE, err := joseutil.Encrypt(userInfoJWT, jwk, contentEncAlg)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the user info response: %w", err)
	}

	return userInfoJWE, nil
}

func validateRequest(ctx oidc.Context, t *goidc.Token, tkn string) error {
	if t.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "token expired")
	}

	if !strutil.ContainsOpenID(t.Scopes) {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid scope")
	}

	confirmation := goidc.TokenConfirmation{
		JWKThumbprint:        t.JWKThumbprint,
		ClientCertThumbprint: t.ClientCertThumbprint,
	}
	if err := token.ValidatePoP(ctx, tkn, confirmation); err != nil {
		return err
	}

	return nil
}
