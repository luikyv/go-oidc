package utils

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type ResultChannel struct {
	Result any
	Err    issues.OAuthError
}

func ExtractJarFromRequestObject(
	ctx Context,
	reqObject string,
	client models.Client,
) (
	models.AuthorizationRequest,
	issues.OAuthError,
) {
	jarAlgorithms := ctx.JarSignatureAlgorithms
	if client.JarSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JarSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	jwk := keys[0]
	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	// TODO: Validate the jar expiration time.
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	return jarReq, nil
}

func ValidateProofOfPossesion(
	ctx Context,
	token string,
	tokenType constants.TokenType,
	grantSession models.GrantSession,
) issues.OAuthError {

	if grantSession.JwkThumbprint == "" {
		if tokenType == constants.DpopTokenType {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return issues.NewOAuthError(constants.InvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJwt := ctx.RequestContext.Request.Header.Get(string(constants.DpopHeader))
	if dpopJwt == "" {
		// The session was created with DPoP, then the DPoP header must be passed.
		return issues.NewOAuthError(constants.AccessDenied, "missing DPoP header")
	}

	return ValidateDpopJwt(ctx, dpopJwt, models.DpopClaims{
		HttpMethod:    ctx.RequestContext.Request.Method,
		HttpUri:       ctx.Host + ctx.RequestContext.Request.URL.RequestURI(),
		AccessToken:   token,
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}

func ValidateDpopJwt(ctx Context, dpopJwt string, expectedDpopClaims models.DpopClaims) issues.OAuthError {
	parsedDpopJwt, err := jwt.ParseSigned(dpopJwt, ctx.DpopSignatureAlgorithms)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if len(parsedDpopJwt.Headers) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if parsedDpopJwt.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDpopJwt.Headers[0].JSONWebKey
	if jwk == nil || !jwk.IsPublic() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims models.DpopClaims
	if err := parsedDpopJwt.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if claims.IssuedAt == nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid iat claim")
	}

	if claims.ID == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jti claim")
	}

	if expectedDpopClaims.HttpMethod != "" && dpopClaims.HttpMethod != expectedDpopClaims.HttpMethod {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid htm claim")
	}

	if expectedDpopClaims.HttpUri != "" && dpopClaims.HttpUri != expectedDpopClaims.HttpUri {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid htu claim")
	}

	if expectedDpopClaims.AccessToken != "" && dpopClaims.AccessTokenHash != unit.CreateSha256Hash(expectedDpopClaims.AccessToken) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid ath claim")
	}

	if expectedDpopClaims.JwkThumbprint != "" && unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms) != expectedDpopClaims.JwkThumbprint {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	return nil
}

func GetTokenId(ctx Context, token string) (string, issues.OAuthError) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return token, nil
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return "", issues.NewOAuthError(constants.InvalidRequest, "invalid header kid")
	}

	keyId := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.GetPublicKey(keyId)
	if !ok {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	claims := jwt.Claims{}
	if err := parsedToken.Claims(publicKey, &claims); err != nil {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if claims.ID == "" {
		return "", issues.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return claims.ID, nil
}

func MakeIdToken(ctx Context, grantOptions models.GrantOptions) string {

	privateJwk := ctx.GetIdTokenPrivateKey(grantOptions.IdTokenOptions)
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

func makeJwtToken(ctx Context, grantOptions models.GrantOptions) models.Token {
	privateJwk := ctx.GetTokenPrivateKey(grantOptions.TokenOptions)
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenIdClaim):  jwtId,
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.SubjectClaim):  grantOptions.Subject,
		string(constants.ScopeClaim):    grantOptions.Scopes,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantOptions.ExpiresInSecs,
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

func makeOpaqueToken(ctx Context, grantOptions models.GrantOptions) models.Token {
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

func MakeToken(ctx Context, grantOptions models.GrantOptions) models.Token {
	if grantOptions.TokenFormat == constants.JwtTokenFormat {
		return makeJwtToken(ctx, grantOptions)
	} else {
		return makeOpaqueToken(ctx, grantOptions)
	}
}

func GenerateGrantSession(ctx Context, grantOptions models.GrantOptions) models.GrantSession {
	nowTimestamp := unit.GetTimestampNow()
	token := MakeToken(ctx, grantOptions)

	sessionId := grantOptions.SessionId
	if sessionId == "" {
		sessionId = uuid.NewString()
	}

	createAtTimestamp := grantOptions.CreatedAtTimestamp
	if createAtTimestamp == 0 {
		createAtTimestamp = nowTimestamp
	}

	grantSession := models.GrantSession{
		Id:                      sessionId,
		JwkThumbprint:           token.JwkThumbprint,
		TokenId:                 token.Id,
		Token:                   token.Value,
		TokenType:               token.Type,
		TokenFormat:             token.Format,
		ExpiresInSecs:           grantOptions.ExpiresInSecs,
		CreatedAtTimestamp:      createAtTimestamp,
		RenewedAtTimestamp:      nowTimestamp,
		Subject:                 grantOptions.Subject,
		ClientId:                grantOptions.ClientId,
		Scopes:                  grantOptions.Scopes,
		Nonce:                   grantOptions.Nonce,
		AdditionalTokenClaims:   grantOptions.AdditionalTokenClaims,
		AdditionalIdTokenClaims: grantOptions.AdditionalIdTokenClaims,
	}

	if grantOptions.ShouldGenerateRefreshToken() {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.RefreshTokenExpiresIn = grantOptions.RefreshLifetimeSecs
	}

	if grantOptions.ShouldGenerateIdToken() {
		grantSession.IdToken = MakeIdToken(ctx, grantOptions)
	}

	if grantOptions.ShouldSaveSession() {
		ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	return grantSession
}
