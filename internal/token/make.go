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

func MakeIDToken(ctx oidc.Context, c *goidc.Client, opts IDTokenOptions) (string, error) {
	idToken, err := makeIDToken(ctx, c, opts)
	if err != nil {
		return "", err
	}

	// If encryption is disabled, just return the signed ID token.
	if !ctx.IDTokenEncIsEnabled || c.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	return encryptIDToken(ctx, c, idToken)
}

// makeAccessToken generates an access token value. It returns the JWT or opaque string.
func makeAccessToken(ctx oidc.Context, tkn *goidc.Token, grant *goidc.Grant) (string, error) {
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

func makeIDToken(ctx oidc.Context, c *goidc.Client, opts IDTokenOptions) (string, error) {
	alg := ctx.IDTokenDefaultSigAlg
	if c.IDTokenSigAlg != "" && slices.Contains(ctx.IDTokenSigAlgs, c.IDTokenSigAlg) {
		alg = c.IDTokenSigAlg
	}

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

	if alg != goidc.None {
		if opts.AccessToken != "" {
			claims[goidc.ClaimAccessTokenHash] = hashutil.HalfHash(opts.AccessToken, alg)
		}

		if opts.AuthorizationCode != "" {
			claims[goidc.ClaimAuthzCodeHash] = hashutil.HalfHash(opts.AuthorizationCode, alg)
		}

		if opts.State != "" {
			claims[goidc.ClaimStateHash] = hashutil.HalfHash(opts.State, alg)
		}

		if opts.RefreshToken != "" {
			claims[goidc.ClaimRefreshTokenHash] = hashutil.HalfHash(opts.RefreshToken, alg)
		}

		if opts.AuthReqID != "" {
			claims[goidc.ClaimAuthReqID] = hashutil.HalfHash(opts.AuthReqID, alg)
		}
	}

	if opts.Nonce != "" {
		claims[goidc.ClaimNonce] = opts.Nonce
	}

	maps.Copy(claims, opts.Claims)

	if alg == goidc.None {
		return joseutil.Unsigned(claims), nil
	}
	idToken, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the id token: %w", err)
	}
	return idToken, nil
}

func encryptIDToken(ctx oidc.Context, c *goidc.Client, idToken string) (string, error) {
	jwk, err := client.JWKByAlg(ctx, c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	contentEncAlg := ctx.IDTokenDefaultContentEncAlg
	if c.IDTokenContentEncAlg != "" && slices.Contains(ctx.IDTokenContentEncAlgs, c.IDTokenContentEncAlg) {
		contentEncAlg = c.IDTokenContentEncAlg
	}

	encIDToken, err := joseutil.Encrypt(idToken, jwk, contentEncAlg)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not encrypt the id token", err)
	}
	return encIDToken, nil
}
