package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func MakeIDToken(
	ctx Context,
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
	ctx Context,
	client goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	if grantOptions.TokenFormat == goidc.JWTTokenFormat {
		return makeJWTToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}

func makeIDToken(
	ctx Context,
	client goidc.Client,
	idTokenOpts IDTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	privateJWK := ctx.GetIDTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJWK.GetAlgorithm())
	timestampNow := goidc.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		goidc.IssuerClaim:   ctx.Host,
		goidc.SubjectClaim:  idTokenOpts.Subject,
		goidc.AudienceClaim: idTokenOpts.ClientID,
		goidc.IssuedAtClaim: timestampNow,
		goidc.ExpiryClaim:   timestampNow + ctx.IDTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[goidc.AccessTokenHashClaim] = GenerateHalfHashClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[goidc.AuthorizationCodeHashClaim] = GenerateHalfHashClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[goidc.StateHashClaim] = GenerateHalfHashClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIDTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJWK.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.GetKeyID()),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return idToken, nil
}

func encryptIDToken(
	ctx Context,
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
	ctx Context,
	client goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	privateJWK := ctx.GetTokenSignatureKey(grantOptions.TokenOptions)
	jwtID := uuid.NewString()
	timestampNow := goidc.GetTimestampNow()
	claims := map[string]any{
		goidc.TokenIDClaim:  jwtID,
		goidc.IssuerClaim:   ctx.Host,
		goidc.SubjectClaim:  grantOptions.Subject,
		goidc.ClientIDClaim: client.ID,
		goidc.ScopeClaim:    grantOptions.GrantedScopes,
		goidc.IssuedAtClaim: timestampNow,
		goidc.ExpiryClaim:   timestampNow + grantOptions.TokenLifetimeSecs,
	}

	if grantOptions.GrantedAuthorizationDetails != nil {
		claims[goidc.AuthorizationDetailsClaim] = grantOptions.GrantedAuthorizationDetails
	}

	tokenType := goidc.BearerTokenType
	confirmation := make(map[string]string)
	// DPoP token binding.
	dpopJWT, ok := ctx.GetDPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.DPOPTokenType
		jkt = GenerateJWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = GenerateBase64URLSha256Hash(string(clientCert.Raw))
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
		return Token{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	accessToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return Token{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return Token{
		ID:                    jwtID,
		Format:                goidc.JWTTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JWKThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}

func makeOpaqueToken(
	ctx Context,
	_ goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	Token,
	goidc.OAuthError,
) {
	accessToken := goidc.GenerateRandomString(grantOptions.OpaqueTokenLength, grantOptions.OpaqueTokenLength)
	tokenType := goidc.BearerTokenType

	// DPoP token binding.
	dpopJWT, ok := ctx.GetDPOPJWT()
	jkt := ""
	if ctx.DPOPIsEnabled && ok {
		tokenType = goidc.DPOPTokenType
		jkt = GenerateJWKThumbprint(dpopJWT, ctx.DPOPSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TLSBoundTokensIsEnabled && ok {
		certThumbprint = GenerateBase64URLSha256Hash(string(clientCert.Raw))
	}

	return Token{
		ID:                    accessToken,
		Format:                goidc.OpaqueTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JWKThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}
