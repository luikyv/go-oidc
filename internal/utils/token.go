package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func MakeIDToken(
	ctx *Context,
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

func MakeToken(
	ctx *Context,
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

func makeIDToken(
	ctx *Context,
	client *goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.IDTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.Algorithm())
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
		claims[goidc.ClaimAccessTokenHash] = HalfHashIDTokenClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthorizationCodeHash] = HalfHashIDTokenClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[goidc.ClaimStateHash] = HalfHashIDTokenClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.Key()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID()),
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
	ctx *Context,
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
	ctx *Context,
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
	dpopJWT, ok := ctx.DPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPOP
		jkt = JWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.ClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = HashBase64URLSHA256(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm()), Key: privateJWK.Key()},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJWK.KeyID()),
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
	ctx *Context,
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
	dpopJWT, ok := ctx.DPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPOP
		jkt = JWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.ClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = HashBase64URLSHA256(string(clientCert.Raw))
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
