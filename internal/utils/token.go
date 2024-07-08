package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func MakeIDToken(
	ctx OAuthContext,
	client goidc.Client,
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
	ctx OAuthContext,
	client goidc.Client,
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
	ctx OAuthContext,
	client goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.GetIDTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.GetAlgorithm())
	timestampNow := goidc.TimestampNow()

	// Set the token claims.
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimSubject:  idTokenOpts.Subject,
		goidc.ClaimAudience: idTokenOpts.ClientID,
		goidc.ClaimIssuedAt: timestampNow,
		goidc.ClaimExpiry:   timestampNow + ctx.IDTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[goidc.ClaimAccessTokenHash] = GenerateHalfHashClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[goidc.ClaimAuthorizationCodeHash] = GenerateHalfHashClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[goidc.ClaimStateHash] = GenerateHalfHashClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.GetKeyID()),
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
	ctx OAuthContext,
	client goidc.Client,
	userInfoJWT string,
) (
	string,
	goidc.OAuthError,
) {
	jwk, oauthErr := client.GetIDTokenEncryptionJWK()
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
	ctx OAuthContext,
	client goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	privateJWK := ctx.GetTokenSignatureKey(grantOptions.TokenOptions)
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
	dpopJWT, ok := ctx.GetDPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPOP
		jkt = GenerateJWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = GenerateBase64URLSHA256Hash(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.GetAlgorithm()), Key: privateJWK.GetKey()},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJWK.GetKeyID()),
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
	ctx OAuthContext,
	_ goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	accessToken := goidc.RandomString(grantOptions.OpaqueTokenLength, grantOptions.OpaqueTokenLength)
	tokenType := goidc.TokenTypeBearer

	// DPoP token binding.
	dpopJWT, ok := ctx.GetDPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.TokenTypeDPOP
		jkt = GenerateJWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = GenerateBase64URLSHA256Hash(string(clientCert.Raw))
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
