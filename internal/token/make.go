package token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientutil"
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
	if !ctx.UserEncIsEnabled || client.IDTokenKeyEncAlg == "" {
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
	if ctx.UserInfoSigAlgsContainsNone() && client.IDTokenSigAlg == goidc.NoneSignatureAlgorithm {
		return makeUnsignedIDToken(ctx, client, opts)
	}

	jwk, err := ctx.IDTokenSigKeyForClient(client)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"internal error", err)
	}

	claims, err := idTokenClaims(ctx, client, opts, jose.SignatureAlgorithm(jwk.Algorithm))
	if err != nil {
		return "", err
	}
	idToken, err := jwtutil.Sign(claims, jwk,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not sign the id token", err)
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
	claims, err := idTokenClaims(ctx, client, opts, goidc.NoneSignatureAlgorithm)
	if err != nil {
		return "", err
	}
	return jwtutil.Unsigned(claims)
}

func idTokenClaims(
	ctx oidc.Context,
	client *goidc.Client,
	opts IDTokenOptions,
	sigAlg jose.SignatureAlgorithm,
) (
	map[string]any,
	error,
) {
	now := timeutil.TimestampNow()

	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	sub, err := ctx.ExportableSubject(opts.Subject, client)
	if err != nil {
		return nil, err
	}

	claims[goidc.ClaimSubject] = sub

	// Avoid an empty client ID claim for anonymous clients.
	if client.ID != "" {
		claims[goidc.ClaimAudience] = client.ID
	}

	if opts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = halfHashIDTokenClaim(opts.AccessToken, sigAlg)
	}

	if opts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthzCodeHash] = halfHashIDTokenClaim(opts.AuthorizationCode, sigAlg)
	}

	if opts.State != "" {
		claims[goidc.ClaimStateHash] = halfHashIDTokenClaim(opts.State, sigAlg)
	}

	if opts.RefreshToken != "" {
		claims[goidc.ClaimRefreshTokenHash] = halfHashIDTokenClaim(opts.RefreshToken, sigAlg)
	}

	if opts.AuthReqID != "" {
		claims[goidc.ClaimAuthReqID] = halfHashIDTokenClaim(opts.AuthReqID, sigAlg)
	}

	for k, v := range opts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	return claims, nil
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
		contentEncAlg = ctx.UserDefaultContentEncAlg
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
	privateJWK, err := ctx.PrivateKey(opts.JWTSignatureKeyID)
	if err != nil {
		return Token{}, fmt.Errorf("could not find key with id %s: %w", opts.JWTSignatureKeyID, err)
	}

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

	// RFC9068. "...This specification registers the "application/at+jwt" media type,
	// which can be used to indicate that the content is a JWT access token."
	accessToken, err := jwtutil.Sign(claims, privateJWK,
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJWK.KeyID))
	if err != nil {
		return Token{}, goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not sign the access token", err)
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

func halfHashIDTokenClaim(claim string, alg jose.SignatureAlgorithm) string {
	var hash hash.Hash
	switch alg {
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		hash = sha512.New384()
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		hash = sha512.New()
	default:
		hash = sha256.New()
	}

	hash.Write([]byte(claim))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

func hashBase64URLSHA256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
