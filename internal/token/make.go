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
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Token struct {
	ID                    string
	Format                goidc.TokenFormat
	Value                 string
	Type                  goidc.TokenType
	JWKThumbprint         string
	CertificateThumbprint string
}

type IDTokenOptions struct {
	Subject                 string
	AdditionalIDTokenClaims map[string]any
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

func newIDTokenOptions(grantOpts goidc.GrantOptions) IDTokenOptions {
	return IDTokenOptions{
		Subject:                 grantOpts.Subject,
		AdditionalIDTokenClaims: grantOpts.AdditionalIDTokenClaims,
	}
}

func MakeIDToken(
	ctx *utils.Context,
	client *goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	idToken, err := makeIDToken(ctx, client, idTokenOpts)
	if err != nil {
		return "", err
	}

	// If encryption is disabled, just return the signed ID token.
	if client.IDTokenKeyEncryptionAlgorithm == "" {
		return idToken, nil
	}

	idToken, err = encryptIDToken(ctx, client, idToken)
	if err != nil {
		return "", err
	}

	return idToken, nil
}

func Make(
	ctx *utils.Context,
	client *goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	if grantOptions.TokenFormat == goidc.TokenFormatJWT {
		return makeJWTToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}

func EncryptJWT(
	_ *utils.Context,
	jwtString string,
	encryptionJWK jose.JSONWebKey,
	contentKeyEncryptionAlgorithm jose.ContentEncryption,
) (
	string,
	goidc.OAuthError,
) {
	encrypter, err := jose.NewEncrypter(
		contentKeyEncryptionAlgorithm,
		jose.Recipient{Algorithm: jose.KeyAlgorithm(encryptionJWK.Algorithm), Key: encryptionJWK.Key, KeyID: encryptionJWK.KeyID},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	encryptedUserInfoJWTJWE, err := encrypter.Encrypt([]byte(jwtString))
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	encryptedUserInfoString, err := encryptedUserInfoJWTJWE.CompactSerialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return encryptedUserInfoString, nil
}

func makeIDToken(
	ctx *utils.Context,
	client *goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.IDTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.Algorithm)
	timestampNow := goidc.TimestampNow()

	// Set the token claims.
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  idTokenOpts.Subject,
		goidc.ClaimAudience: client.ID,
		goidc.ClaimIssuedAt: timestampNow,
		goidc.ClaimExpiry:   timestampNow + ctx.IDTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = halfHashIDTokenClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthorizationCodeHash] = halfHashIDTokenClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[goidc.ClaimStateHash] = halfHashIDTokenClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return idToken, nil
}

func encryptIDToken(
	ctx *utils.Context,
	client *goidc.Client,
	userInfoJWT string,
) (
	string,
	goidc.OAuthError,
) {
	jwk, oauthErr := client.IDTokenEncryptionJWK()
	if oauthErr != nil {
		return "", oauthErr
	}

	encryptedIDToken, oauthErr := EncryptJWT(ctx, userInfoJWT, jwk, client.IDTokenContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedIDToken, nil
}

// TODO: Make it simpler. Create a confirmation object.
func makeJWTToken(
	ctx *utils.Context,
	client *goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	privateJWK := ctx.TokenSignatureKey(grantOptions.TokenOptions)
	jwtID := uuid.NewString()
	timestampNow := goidc.TimestampNow()
	claims := map[string]any{
		goidc.ClaimTokenID:  jwtID,
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  grantOptions.Subject,
		goidc.ClaimClientID: client.ID,
		goidc.ClaimScope:    grantOptions.GrantedScopes,
		goidc.ClaimIssuedAt: timestampNow,
		goidc.ClaimExpiry:   timestampNow + grantOptions.TokenLifetimeSecs,
	}

	if grantOptions.GrantedAuthorizationDetails != nil {
		claims[goidc.ClaimAuthorizationDetails] = grantOptions.GrantedAuthorizationDetails
	}

	tokenType := goidc.TokenTypeBearer
	confirmation := make(map[string]string)
	// DPoP token binding.
	dpopJWT, ok := ctx.DPoPJWT()
	jkt := ""
	if ctx.DPoPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPoP
		jkt = jwkThumbprint(dpopJWT, ctx.DPoPSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.ClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJWK.KeyID),
	)
	if err != nil {
		return Token{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	accessToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return Token{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
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
	ctx *utils.Context,
	_ *goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	accessToken, err := goidc.RandomString(grantOptions.OpaqueTokenLength)
	if err != nil {
		return Token{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	tokenType := goidc.TokenTypeBearer

	// DPoP token binding.
	dpopJWT, ok := ctx.DPoPJWT()
	jkt := ""
	if ctx.DPoPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPoP
		jkt = jwkThumbprint(dpopJWT, ctx.DPoPSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.ClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
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
	jkt, _ := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(jkt)
}

func hashBase64URLSHA256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
