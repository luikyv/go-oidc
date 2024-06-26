package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func MakeIdToken(
	ctx Context,
	client goidc.Client,
	idTokenOpts models.IdTokenOptions,
) (
	string,
	goidc.OAuthError,
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
	client goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	models.Token,
	goidc.OAuthError,
) {
	if grantOptions.TokenFormat == goidc.JwtTokenFormat {
		return makeJwtToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}

func makeIdToken(
	ctx Context,
	client goidc.Client,
	idTokenOpts models.IdTokenOptions,
) (
	string,
	goidc.OAuthError,
) {
	privateJwk := ctx.GetIdTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.GetAlgorithm())
	timestampNow := goidc.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		goidc.IssuerClaim:   ctx.Host,
		goidc.SubjectClaim:  idTokenOpts.Subject,
		goidc.AudienceClaim: idTokenOpts.ClientId,
		goidc.IssuedAtClaim: timestampNow,
		goidc.ExpiryClaim:   timestampNow + ctx.IdTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[goidc.AccessTokenHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[goidc.AuthorizationCodeHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[goidc.StateHashClaim] = unit.GenerateHalfHashClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIdTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.GetKeyId()),
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

func encryptIdToken(
	ctx Context,
	client goidc.Client,
	userInfoJwt string,
) (
	string,
	goidc.OAuthError,
) {
	jwk, oauthErr := client.GetIdTokenEncryptionJwk()
	if oauthErr != nil {
		return "", oauthErr
	}

	encryptedIdToken, oauthErr := EncryptJwt(ctx, userInfoJwt, jwk, client.IdTokenContentEncryptionAlgorithm)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedIdToken, nil
}

// TODO: Make it simpler. Create a confirmation object.
func makeJwtToken(
	ctx Context,
	client goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	models.Token,
	goidc.OAuthError,
) {
	privateJwk := ctx.GetTokenSignatureKey(grantOptions.TokenOptions)
	jwtId := uuid.NewString()
	timestampNow := goidc.GetTimestampNow()
	claims := map[string]any{
		goidc.TokenIdClaim:  jwtId,
		goidc.IssuerClaim:   ctx.Host,
		goidc.SubjectClaim:  grantOptions.Subject,
		goidc.ClientIdClaim: client.Id,
		goidc.ScopeClaim:    grantOptions.GrantedScopes,
		goidc.IssuedAtClaim: timestampNow,
		goidc.ExpiryClaim:   timestampNow + grantOptions.TokenExpiresInSecs,
	}

	if grantOptions.GrantedAuthorizationDetails != nil {
		claims[goidc.AuthorizationDetailsClaim] = grantOptions.GrantedAuthorizationDetails
	}

	tokenType := goidc.BearerTokenType
	confirmation := make(map[string]string)
	// DPoP token binding.
	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = goidc.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}
	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TlsBoundTokensIsEnabled && ok {
		certThumbprint = unit.GenerateBase64UrlSha256Hash(string(clientCert.Raw))
		confirmation["x5t#S256"] = certThumbprint
	}
	if len(confirmation) != 0 {
		claims["cnf"] = confirmation
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJwk.GetAlgorithm()), Key: privateJwk.GetKey()},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", privateJwk.GetKeyId()),
	)
	if err != nil {
		return models.Token{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	accessToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return models.Token{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return models.Token{
		Id:                    jwtId,
		Format:                goidc.JwtTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JwkThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}

func makeOpaqueToken(
	ctx Context,
	_ goidc.Client,
	grantOptions goidc.GrantOptions,
) (
	models.Token,
	goidc.OAuthError,
) {
	accessToken := goidc.GenerateRandomString(grantOptions.OpaqueTokenLength, grantOptions.OpaqueTokenLength)
	tokenType := goidc.BearerTokenType

	// DPoP token binding.
	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = goidc.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
	}

	// TLS token binding.
	clientCert, ok := ctx.GetClientCertificate()
	certThumbprint := ""
	if ctx.TlsBoundTokensIsEnabled && ok {
		certThumbprint = unit.GenerateBase64UrlSha256Hash(string(clientCert.Raw))
	}

	return models.Token{
		Id:                    accessToken,
		Format:                goidc.OpaqueTokenFormat,
		Value:                 accessToken,
		Type:                  tokenType,
		JwkThumbprint:         jkt,
		CertificateThumbprint: certThumbprint,
	}, nil
}
