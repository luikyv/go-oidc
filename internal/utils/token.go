package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func MakeIdToken(
	ctx Context,
	client models.Client,
	idTokenOpts models.IdTokenOptions,
) (
	string,
	models.OAuthError,
) {
	idToken, err := makeIdToken(ctx, client, idTokenOpts)
	if err != nil {
		return "", err
	}

	// If encryption is disabled, just return the signed ID token.
	if client.IdTokenKeyEncryptionAlgorithm == "" {
		return idToken, nil
	}

	idToken, err = encryptIdToken(ctx, client, idToken)
	if err != nil {
		return "", err
	}

	return idToken, nil
}

func MakeToken(
	ctx Context,
	client models.Client,
	grantOptions models.GrantOptions,
) models.Token {
	if grantOptions.TokenFormat == constants.JwtTokenFormat {
		return makeJwtToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}

func makeIdToken(
	ctx Context,
	client models.Client,
	idTokenOpts models.IdTokenOptions,
) (
	string,
	models.OAuthError,
) {
	privateJwk := ctx.GetIdTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.Algorithm)
	timestampNow := unit.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		constants.IssuerClaim:   ctx.Host,
		constants.SubjectClaim:  idTokenOpts.Subject,
		constants.AudienceClaim: idTokenOpts.ClientId,
		constants.IssuedAtClaim: timestampNow,
		constants.ExpiryClaim:   timestampNow + ctx.IdTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[constants.AccessTokenHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[constants.AuthorizationCodeHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[constants.StateHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIdTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	return idToken, nil
}

func encryptIdToken(
	_ Context,
	client models.Client,
	idToken string,
) (
	string,
	models.OAuthError,
) {
	jwk, oauthErr := client.GetIdTokenEncryptionJwk()
	if oauthErr != nil {
		return "", oauthErr
	}

	encrypter, err := jose.NewEncrypter(
		client.IdTokenContentEncryptionAlgorithm,
		jose.Recipient{Algorithm: client.IdTokenKeyEncryptionAlgorithm, Key: jwk.Key, KeyID: jwk.KeyID},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	encryptedIdTokenJwe, err := encrypter.Encrypt([]byte(idToken))
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	encryptedIdTokenString, err := encryptedIdTokenJwe.CompactSerialize()
	if err != nil {
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}

	return encryptedIdTokenString, nil
}

// TODO: Make it simpler. Create a confirmation object.
func makeJwtToken(
	ctx Context,
	client models.Client,
	grantOptions models.GrantOptions,
) models.Token {
	privateJwk := ctx.GetTokenSignatureKey(grantOptions.TokenOptions)
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		constants.TokenIdClaim:  jwtId,
		constants.IssuerClaim:   ctx.Host,
		constants.SubjectClaim:  grantOptions.Subject,
		constants.ClientIdClaim: client.Id,
		constants.ScopeClaim:    grantOptions.GrantedScopes,
		constants.IssuedAtClaim: timestampNow,
		constants.ExpiryClaim:   timestampNow + grantOptions.TokenExpiresInSecs,
	}
	tokenType := constants.BearerTokenType

	confirmation := make(map[string]string)
	// DPoP token binding.
	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TlsBoundTokensIsEnabled && ok {
		certThumbprint = unit.GenerateSha256Thumbprint(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJwk.Algorithm), Key: privateJwk.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJwk.KeyID),
	)

	accessToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return models.Token{
		Id:                    jwtId,
		Format:                constants.JwtTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JwkThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}
}

func makeOpaqueToken(
	ctx Context,
	_ models.Client,
	grantOptions models.GrantOptions,
) models.Token {
	accessToken := unit.GenerateRandomString(grantOptions.OpaqueTokenLength, grantOptions.OpaqueTokenLength)
	tokenType := constants.BearerTokenType

	// DPoP token binding.
	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TlsBoundTokensIsEnabled && ok {
		certThumbprint = unit.GenerateSha256Thumbprint(string(clientCert.Raw))
	}

	return models.Token{
		Id:                    accessToken,
		Format:                constants.OpaqueTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JwkThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}
}
