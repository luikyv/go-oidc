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
	if client.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	idToken, err = encryptIDToken(ctx, client, idToken)
	if err != nil {
		return "", err
	}

	return idToken, nil
}

func Make(
	ctx oidc.Context,
	grantInfo goidc.GrantInfo,
) (
	Token,
	error,
) {
	opts := ctx.TokenOptions(grantInfo)
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
	jwk, ok := ctx.IDTokenSigKeyForClient(client)
	if !ok {
		return "", goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"the id token signing algorithm defined for the client is not available")
	}
	sigAlg := jose.SignatureAlgorithm(jwk.Algorithm)
	now := timeutil.TimestampNow()

	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  opts.Subject,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	// Avoid an empty client ID claim for anonymous client.
	if client.ID != "" {
		claims[goidc.ClaimAudience] = client.ID
	}

	if opts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = halfHashIDTokenClaim(
			opts.AccessToken,
			sigAlg,
		)
	}

	if opts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthzCodeHash] = halfHashIDTokenClaim(
			opts.AuthorizationCode,
			sigAlg,
		)
	}

	if opts.State != "" {
		claims[goidc.ClaimStateHash] = halfHashIDTokenClaim(opts.State, sigAlg)
	}

	for k, v := range opts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	idToken, err := jwtutil.Sign(claims, jwk,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID))
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not sign the id token", err)
	}

	return idToken, nil
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
		return "", goidc.Errorf(goidc.ErrorCodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	encIDToken, err := jwtutil.Encrypt(userInfoJWT, jwk, c.IDTokenContentEncAlg)
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInvalidRequest,
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
	privateJWK, ok := ctx.PrivateKey(opts.JWTSignatureKeyID)
	if !ok {
		return Token{}, fmt.Errorf("could not find key with id: %s", opts.JWTSignatureKeyID)
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

	if grantInfo.GrantedAuthorizationDetails != nil {
		claims[goidc.ClaimAuthDetails] = grantInfo.GrantedAuthorizationDetails
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
		return Token{}, goidc.Errorf(goidc.ErrorCodeInternalError,
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
	accessToken, err := strutil.Random(opts.OpaqueLength)
	if err != nil {
		return Token{}, goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not generate the opaque token", err)
	}

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
	case jose.RS256, jose.ES256, jose.PS256, jose.HS256:
		hash = sha256.New()
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		hash = sha512.New384()
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		hash = sha512.New()
	default:
		hash = nil
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
