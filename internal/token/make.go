package token

import (
	"fmt"
	"maps"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func MakeIDToken(ctx oidc.Context, client *goidc.Client, grant *goidc.Grant, opts IDTokenOptions) (string, error) {
	idToken, err := makeIDToken(ctx, client, grant, opts)
	if err != nil {
		return "", err
	}

	// If encryption is disabled, just return the signed ID token.
	if !ctx.IDTokenEncIsEnabled || client.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	return encryptIDToken(ctx, client, idToken)
}

// Make generates an access token value. It returns the JWT or opaque string.
func Make(ctx oidc.Context, tkn *goidc.Token, grant *goidc.Grant) (string, error) {
	if tkn.Format == goidc.TokenFormatOpaque {
		return tkn.ID, nil
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimTokenID:  tkn.ID,
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimSubject:  tkn.Subject,
		goidc.ClaimScope:    tkn.Scopes,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   tkn.ExpiresAtTimestamp,
	}

	if tkn.ClientID != "" {
		claims[goidc.ClaimClientID] = tkn.ClientID
	}

	if tkn.AuthDetails != nil {
		claims[goidc.ClaimAuthDetails] = tkn.AuthDetails
	}

	if tkn.Resources != nil {
		claims[goidc.ClaimAudience] = tkn.Resources
	}

	confirmation := make(map[string]string)
	if tkn.JWKThumbprint != "" {
		confirmation["jkt"] = tkn.JWKThumbprint
	}
	if tkn.ClientCertThumbprint != "" {
		confirmation["x5t#S256"] = tkn.ClientCertThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	maps.Copy(claims, ctx.TokenClaims(grant))

	if tkn.SigAlg == goidc.None {
		return joseutil.Unsigned(claims), nil
	}

	accessToken, err := ctx.Sign(claims, tkn.SigAlg, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return "", fmt.Errorf("could not sign the access token: %w", err)
	}

	return accessToken, nil
}

func makeIDToken(ctx oidc.Context, c *goidc.Client, grant *goidc.Grant, opts IDTokenOptions) (string, error) {
	if slices.Contains(ctx.IDTokenSigAlgs, goidc.None) && c.IDTokenSigAlg == goidc.None {
		return makeUnsignedIDToken(ctx, c, grant, opts), nil
	}

	alg := ctx.IDTokenDefaultSigAlg
	if c.IDTokenSigAlg != "" {
		alg = c.IDTokenSigAlg
	}
	claims := idTokenClaims(ctx, c, grant, opts, alg)
	idToken, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the id token: %w", err)
	}

	return idToken, nil
}

func makeUnsignedIDToken(ctx oidc.Context, c *goidc.Client, grant *goidc.Grant, opts IDTokenOptions) string {
	claims := idTokenClaims(ctx, c, grant, opts, goidc.None)
	return joseutil.Unsigned(claims)
}

func idTokenClaims(
	ctx oidc.Context,
	c *goidc.Client,
	grant *goidc.Grant,
	opts IDTokenOptions,
	sigAlg goidc.SignatureAlgorithm,
) map[string]any {
	now := timeutil.TimestampNow()

	claims := map[string]any{
		goidc.ClaimSubject:  ctx.ExportableSubject(opts.Subject, c),
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	// Avoid an empty client ID claim for anonymous clients.
	if c.ID != "" {
		claims[goidc.ClaimAudience] = c.ID
	}

	if opts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = hashutil.HalfHash(opts.AccessToken, sigAlg)
	}

	if opts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthzCodeHash] = hashutil.HalfHash(opts.AuthorizationCode, sigAlg)
	}

	if opts.State != "" {
		claims[goidc.ClaimStateHash] = hashutil.HalfHash(opts.State, sigAlg)
	}

	if opts.RefreshToken != "" {
		claims[goidc.ClaimRefreshTokenHash] = hashutil.HalfHash(opts.RefreshToken, sigAlg)
	}

	if opts.AuthReqID != "" {
		claims[goidc.ClaimAuthReqID] = hashutil.HalfHash(opts.AuthReqID, sigAlg)
	}

	if opts.Nonce != "" {
		claims[goidc.ClaimNonce] = opts.Nonce
	}

	maps.Copy(claims, ctx.IDTokenClaims(grant))

	return claims
}

func encryptIDToken(ctx oidc.Context, c *goidc.Client, userInfoJWT string) (string, error) {
	jwk, err := client.JWKByAlg(ctx, c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	contentEncAlg := c.IDTokenContentEncAlg
	if contentEncAlg == "" {
		contentEncAlg = ctx.IDTokenDefaultContentEncAlg
	}
	encIDToken, err := joseutil.Encrypt(userInfoJWT, jwk, contentEncAlg)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	return encIDToken, nil
}
