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

	tokenInfo, err := token.IntrospectionInfo(ctx, accessToken)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid token", err)
	}

	if !strutil.ContainsOpenID(tokenInfo.Scopes) {
		return response{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid scope")
	}

	if tokenInfo.Confirmation != nil {
		if err := token.ValidatePoP(ctx, accessToken, *tokenInfo.Confirmation); err != nil {
			return response{}, err
		}
	}

	c, err := ctx.Client(tokenInfo.ClientID)
	if err != nil {
		return response{}, err
	}

	grant, err := ctx.GrantByID(tokenInfo.GrantID)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "grant not found", err)
	}

	subType := ctx.DefaultSubIdentifierType
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}

	sub := grant.Subject
	if subType == goidc.SubIdentifierPairwise {
		sub = ctx.PairwiseSubject(grant.Subject, c)
	}

	claims := map[string]any{
		goidc.ClaimSubject: sub,
	}
	maps.Copy(claims, ctx.UserInfoClaims(grant))

	// If the client doesn't require the user info to be signed, just return the claims as a JSON object.
	if c.UserInfoSigAlg == "" {
		return response{
			claims: claims,
		}, nil
	}

	claims[goidc.ClaimIssuer] = ctx.Issuer()
	claims[goidc.ClaimAudience] = c.ID

	alg := ctx.UserInfoDefaultSigAlg
	if c.UserInfoSigAlg != "" && slices.Contains(ctx.UserInfoSigAlgs, c.UserInfoSigAlg) {
		alg = c.UserInfoSigAlg
	}

	claimsJWS, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return response{}, fmt.Errorf("could not sign the user info claims: %w", err)
	}

	// If the client doesn't require the user info to be encrypted, just return the claims as a signed JWT.
	if !ctx.UserInfoEncIsEnabled || c.UserInfoKeyEncAlg == "" {
		return response{
			jwtClaims: claimsJWS,
		}, nil
	}

	jwk, err := client.JWKByAlg(ctx, c, string(c.UserInfoKeyEncAlg))
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not find a jwk to encrypt the user info response", err)
	}

	contentEncAlg := ctx.UserInfoDefaultContentEncAlg
	if c.UserInfoContentEncAlg != "" && slices.Contains(ctx.UserInfoContentEncAlgs, c.UserInfoContentEncAlg) {
		contentEncAlg = c.UserInfoContentEncAlg
	}

	claimsJWE, err := joseutil.Encrypt(claimsJWS, jwk, contentEncAlg)
	if err != nil {
		return response{}, fmt.Errorf("could not encrypt the user info response: %w", err)
	}

	return response{
		jwtClaims: claimsJWE,
	}, nil
}
