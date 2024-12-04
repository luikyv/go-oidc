package token

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func MakeIDToken(
	ctx oidc.Context,
	client *goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	error,
) {
	idToken, err := makeIDToken(ctx, client, idTokenOpts)
	if err != nil {
		return "", err
	}

	// If encryption is disabled, just return the signed ID token.
	if !ctx.IDTokenEncIsEnabled || client.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	return encryptIDToken(ctx, client, idToken)
}

func Make(
	ctx oidc.Context,
	grantInfo goidc.GrantInfo,
	client *goidc.Client,
) (
	Token,
	error,
) {
	opts := ctx.TokenOptions(grantInfo, client)
	if opts.Format == goidc.TokenFormatJWT {
		return makeJWTToken(ctx, grantInfo, opts)
	} else {
		return makeOpaqueToken(ctx, grantInfo, opts)
	}
}

func makeIDToken(
	ctx oidc.Context,
	client *goidc.Client,
	opts IDTokenOptions,
) (
	string,
	error,
) {
	if ctx.IDTokenSigAlgsContainsNone() && client.IDTokenSigAlg == goidc.NoneSignatureAlgorithm {
		return makeUnsignedIDToken(ctx, client, opts)
	}

	sigOpts := goidc.SignatureOptions{
		JWTType:   goidc.JWTTypeBasic,
		Algorithm: ctx.IDTokenDefaultSigAlg,
	}
	if client.IDTokenSigAlg != "" {
		sigOpts.Algorithm = client.IDTokenSigAlg
	}
	claims := idTokenClaims(ctx, client, opts, sigOpts.Algorithm)
	idToken, err := ctx.Sign(claims, sigOpts)
	if err != nil {
		return "", fmt.Errorf("could not sign the id token: %w", err)
	}

	return idToken, nil
}

func makeUnsignedIDToken(
	ctx oidc.Context,
	client *goidc.Client,
	opts IDTokenOptions,
) (
	string,
	error,
) {
	claims := idTokenClaims(ctx, client, opts, goidc.NoneSignatureAlgorithm)
	return jwtutil.Unsigned(claims)
}

func idTokenClaims(
	ctx oidc.Context,
	client *goidc.Client,
	opts IDTokenOptions,
	sigAlg jose.SignatureAlgorithm,
) map[string]any {
	now := timeutil.TimestampNow()

	claims := map[string]any{
		goidc.ClaimSubject:  ctx.ExportableSubject(opts.Subject, client),
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	// Avoid an empty client ID claim for anonymous clients.
	if client.ID != "" {
		claims[goidc.ClaimAudience] = client.ID
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

	for k, v := range opts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	return claims
}

func encryptIDToken(
	ctx oidc.Context,
	c *goidc.Client,
	userInfoJWT string,
) (
	string,
	error,
) {
	jwk, err := clientutil.JWKByAlg(ctx, c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	contentEncAlg := c.IDTokenContentEncAlg
	if contentEncAlg == "" {
		contentEncAlg = ctx.IDTokenDefaultContentEncAlg
	}
	encIDToken, err := jwtutil.Encrypt(userInfoJWT, jwk, contentEncAlg)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	return encIDToken, nil
}

func makeJWTToken(
	ctx oidc.Context,
	grantInfo goidc.GrantInfo,
	opts goidc.TokenOptions,
) (
	Token,
	error,
) {
	jwtID := uuid.NewString()
	timestampNow := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimTokenID:  jwtID,
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  grantInfo.Subject,
		goidc.ClaimScope:    grantInfo.ActiveScopes,
		goidc.ClaimIssuedAt: timestampNow,
		goidc.ClaimExpiry:   timestampNow + opts.LifetimeSecs,
	}

	if grantInfo.ClientID != "" {
		claims[goidc.ClaimClientID] = grantInfo.ClientID
	}

	if grantInfo.ActiveAuthDetails != nil {
		claims[goidc.ClaimAuthDetails] = grantInfo.ActiveAuthDetails
	}

	if grantInfo.ActiveResources != nil {
		claims[goidc.ClaimAudience] = grantInfo.ActiveResources
	}

	tokenType := goidc.TokenTypeBearer
	confirmation := make(map[string]string)
	if grantInfo.JWKThumbprint != "" {
		tokenType = goidc.TokenTypeDPoP
		confirmation["jkt"] = grantInfo.JWKThumbprint
	}
	if grantInfo.ClientCertThumbprint != "" {
		confirmation["x5t#S256"] = grantInfo.ClientCertThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantInfo.AdditionalTokenClaims {
		claims[k] = v
	}

	accessToken, err := ctx.Sign(claims, goidc.SignatureOptions{
		Algorithm: opts.JWTSigAlg,
		JWTType:   goidc.JWTTypeAccessToken,
	})
	if err != nil {
		return Token{}, fmt.Errorf("could not sign the access token: %w", err)
	}

	return Token{
		ID:           jwtID,
		Format:       goidc.TokenFormatJWT,
		Value:        accessToken,
		Type:         tokenType,
		LifetimeSecs: opts.LifetimeSecs,
	}, nil
}

func makeOpaqueToken(
	_ oidc.Context,
	grantInfo goidc.GrantInfo,
	opts goidc.TokenOptions,
) (
	Token,
	error,
) {
	accessToken := strutil.Random(opts.OpaqueLength)
	tokenType := goidc.TokenTypeBearer
	if grantInfo.JWKThumbprint != "" {
		tokenType = goidc.TokenTypeDPoP
	}

	return Token{
		ID:           accessToken,
		Format:       goidc.TokenFormatOpaque,
		Value:        accessToken,
		Type:         tokenType,
		LifetimeSecs: opts.LifetimeSecs,
	}, nil
}
