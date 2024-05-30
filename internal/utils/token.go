package utils

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func MakeIdToken(ctx Context, client models.Client, grantOptions models.GrantOptions) string {

	privateJwk := ctx.GetIdTokenSignatureKey(client)
	signatureAlgorithm := jose.SignatureAlgorithm(privateJwk.Algorithm)
	timestampNow := unit.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.SubjectClaim):  grantOptions.Subject,
		string(constants.AudienceClaim): grantOptions.ClientId,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + ctx.IdTokenExpiresInSecs,
	}

	if grantOptions.Nonce != "" {
		claims[string(constants.NonceClaim)] = grantOptions.Nonce
	}

	if grantOptions.UserAuthenticatedAtTimestamp != 0 {
		claims[string(constants.AuthenticationTimeClaim)] = grantOptions.UserAuthenticatedAtTimestamp
	}

	if len(grantOptions.UserAuthenticationMethodReferences) != 0 {
		claims[string(constants.AuthenticationMethodReferencesClaim)] = grantOptions.UserAuthenticationMethodReferences
	}

	if grantOptions.AccessToken != "" {
		claims[string(constants.AccessTokenHashClaim)] = unit.GenerateHalfHashClaim(grantOptions.AccessToken, signatureAlgorithm)
	}

	if grantOptions.AuthorizationCode != "" {
		claims[string(constants.AuthorizationCodeHashClaim)] = unit.GenerateHalfHashClaim(grantOptions.AuthorizationCode, signatureAlgorithm)
	}

	if grantOptions.State != "" {
		claims[string(constants.StateHashClaim)] = unit.GenerateHalfHashClaim(grantOptions.State, signatureAlgorithm)
	}

	for k, v := range grantOptions.AdditionalIdTokenClaims {
		claims[k] = v
	}

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: signatureAlgorithm, Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return idToken
}

func makeJwtToken(ctx Context, _ models.Client, grantOptions models.GrantOptions) models.Token {
	privateJwk := ctx.GetTokenSignatureKey(grantOptions.TokenOptions)
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenIdClaim):  jwtId,
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.SubjectClaim):  grantOptions.Subject,
		string(constants.ScopeClaim):    grantOptions.GrantedScopes,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantOptions.TokenExpiresInSecs,
	}

	tokenType := constants.BearerTokenType
	jkt := ""
	if grantOptions.DpopJwt != "" {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(grantOptions.DpopJwt, ctx.DpopSignatureAlgorithms)
		claims["cnf"] = map[string]string{
			"jkt": jkt,
		}
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
		Id:            jwtId,
		Format:        constants.JwtTokenFormat,
		Value:         accessToken,
		Type:          tokenType,
		JwkThumbprint: jkt,
	}
}

func makeOpaqueToken(ctx Context, _ models.Client, grantOptions models.GrantOptions) models.Token {
	accessToken := unit.GenerateRandomString(grantOptions.OpaqueTokenLength, grantOptions.OpaqueTokenLength)
	tokenType := constants.BearerTokenType
	jkt := ""
	if grantOptions.DpopJwt != "" {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(grantOptions.DpopJwt, ctx.DpopSignatureAlgorithms)
	}
	return models.Token{
		Id:            accessToken,
		Format:        constants.OpaqueTokenFormat,
		Value:         accessToken,
		Type:          tokenType,
		JwkThumbprint: jkt,
	}
}

func MakeToken(ctx Context, client models.Client, grantOptions models.GrantOptions) models.Token {
	if grantOptions.TokenFormat == constants.JwtTokenFormat {
		return makeJwtToken(ctx, client, grantOptions)
	} else {
		return makeOpaqueToken(ctx, client, grantOptions)
	}
}
