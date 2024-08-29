package token

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func MakeIDToken(
	ctx *oidc.Context,
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
	ctx *oidc.Context,
	client *goidc.Client,
	grantOptions GrantOptions,
) (
	Token,
	error,
) {
	if grantOptions.Format == goidc.TokenFormatJWT {
		return makeJWTToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}

func makeIDToken(
	ctx *oidc.Context,
	client *goidc.Client,
	opts IDTokenOptions,
) (
	string,
	error,
) {
	jwk := ctx.IDTokenSigKey(client)
	sigAlg := jose.SignatureAlgorithm(jwk.Algorithm)
	now := timeutil.TimestampNow()

	// Set the token claims.
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  opts.Subject,
		goidc.ClaimAudience: client.ID,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	if opts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = halfHashIDTokenClaim(
			opts.AccessToken,
			sigAlg,
		)
	}

	if opts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthorizationCodeHash] = halfHashIDTokenClaim(
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
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not sign the id token", err)
	}

	return idToken, nil
}

func encryptIDToken(
	_ *oidc.Context,
	c *goidc.Client,
	userInfoJWT string,
) (
	string,
	error,
) {
	jwk, err := clientutil.JWKByAlg(c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	encIDToken, err := jwtutil.Encrypt(userInfoJWT, jwk, c.IDTokenContentEncAlg)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not encrypt the id token", err)
	}

	return encIDToken, nil
}

func makeJWTToken(
	ctx *oidc.Context,
	client *goidc.Client,
	grantOptions GrantOptions,
) (
	Token,
	error,
) {
	privateJWK := ctx.TokenSigKey(grantOptions.TokenOptions)
	jwtID := uuid.NewString()
	timestampNow := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimTokenID:  jwtID,
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  grantOptions.Subject,
		goidc.ClaimClientID: client.ID,
		goidc.ClaimScope:    grantOptions.GrantedScopes,
		goidc.ClaimIssuedAt: timestampNow,
		goidc.ClaimExpiry:   timestampNow + grantOptions.LifetimeSecs,
	}

	if grantOptions.GrantedAuthorizationDetails != nil {
		claims[goidc.ClaimAuthorizationDetails] = grantOptions.GrantedAuthorizationDetails
	}

	tokenType := goidc.TokenTypeBearer
	confirmation := make(map[string]string)
	// DPoP token binding.
	dpopJWT, ok := dpopJWT(ctx)
	jkt := ""
	if ctx.DPoPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPoP
		jkt = jwkThumbprint(dpopJWT, ctx.DPoPSigAlgs)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.ClientCert()
	certThumbprint := ""
	if ctx.MTLSTokenBindingIsEnabled && ok {
		certThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalClaims {
		claims[k] = v
	}

	// RFC9068. "...This specification registers the "application/at+jwt" media type,
	// which can be used to indicate that the content is a JWT access token."
	accessToken, err := jwtutil.Sign(claims, privateJWK,
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJWK.KeyID))
	if err != nil {
		return Token{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not sign the access token", err)
	}

	return Token{
		ID:                    jwtID,
		Format:                goidc.TokenFormatJWT,
		Value:                 accessToken,
		Type:                  tokenType,
		JWKThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}

func makeOpaqueToken(
	ctx *oidc.Context,
	_ *goidc.Client,
	grantOptions GrantOptions,
) (
	Token,
	error,
) {
	accessToken, err := strutil.Random(grantOptions.OpaqueLength)
	if err != nil {
		return Token{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate the opaque token", err)
	}
	tokenType := goidc.TokenTypeBearer

	// DPoP token binding.
	dpopJWT, ok := dpopJWT(ctx)
	jkt := ""
	if ctx.DPoPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPoP
		jkt = jwkThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}

	// TLS token binding.
	clientCert, ok := ctx.ClientCert()
	certThumbprint := ""
	if ctx.MTLSTokenBindingIsEnabled && ok {
		certThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
	}

	return Token{
		ID:                    accessToken,
		Format:                goidc.TokenFormatOpaque,
		Value:                 accessToken,
		Type:                  tokenType,
		JWKThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}

func halfHashIDTokenClaim(claimValue string, idTokenAlgorithm jose.SignatureAlgorithm) string {
	var hash hash.Hash
	switch idTokenAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256, jose.HS256:
		hash = sha256.New()
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		hash = sha512.New384()
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		hash = sha512.New()
	default:
		hash = nil
	}

	hash.Write([]byte(claimValue))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

// jwkThumbprint generates a JWK thumbprint for a valid DPoP JWT.
func jwkThumbprint(dpopJWT string, dpopSigningAlgorithms []jose.SignatureAlgorithm) string {
	parsedDPoPJWT, _ := jwt.ParseSigned(dpopJWT, dpopSigningAlgorithms)
	// TODO: handle the error
	jkt, _ := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(jkt)
}

func hashBase64URLSHA256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
