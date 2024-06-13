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
) string {

	privateJwk := ctx.GetIdTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.Algorithm)
	timestampNow := unit.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.SubjectClaim):  idTokenOpts.Subject,
		string(constants.AudienceClaim): idTokenOpts.ClientId,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + ctx.IdTokenExpiresInSecs,
	}

	if idTokenOpts.AccessToken != "" {
		claims[string(constants.AccessTokenHashClaim)] = unit.GenerateHalfHashClaim(idTokenOpts.AccessToken, signatureAlgorithm)
	}

	if idTokenOpts.AuthorizationCode != "" {
		claims[string(constants.AuthorizationCodeHashClaim)] = unit.GenerateHalfHashClaim(idTokenOpts.AuthorizationCode, signatureAlgorithm)
	}

	if idTokenOpts.State != "" {
		claims[string(constants.StateHashClaim)] = unit.GenerateHalfHashClaim(idTokenOpts.State, signatureAlgorithm)
	}

	for k, v := range idTokenOpts.AdditionalIdTokenClaims {
		claims[k] = v
	}

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return idToken
}

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

	confirmation := make(map[string]string)

	tokenType := constants.BearerTokenType
	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
		confirmation["jkt"] = jkt
	}

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

	dpopJwt, ok := ctx.GetDpopJwt()
	jkt := ""
	if ctx.DpopIsEnabled && ok {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms)
	}

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
