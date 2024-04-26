package models

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantMetaInfo struct {
	Id                  string
	ExpiresInSecs       int
	IsRefreshable       bool
	RefreshLifetimeSecs int
	OpenIdKeyId         string
}

//---------------------------------------- Token Makers ----------------------------------------//

type Token struct {
	Id     string
	Format constants.TokenFormat
	Value  string
}

type AccessTokenMaker interface {
	MakeToken(grantMeta GrantMetaInfo, grantCtx GrantContext) Token
}

type OpaqueTokenMaker struct {
	TokenLength int
}

func (maker OpaqueTokenMaker) MakeToken(grantMeta GrantMetaInfo, grantCtx GrantContext) Token {
	accessToken := unit.GenerateRandomString(maker.TokenLength, maker.TokenLength)
	return Token{
		Id:     accessToken,
		Format: constants.Opaque,
		Value:  accessToken,
	}
}

type JWTTokenMaker struct {
	SigningKeyId string
}

func (maker JWTTokenMaker) MakeToken(grantMeta GrantMetaInfo, grantCtx GrantContext) Token {
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenIdClaim):  jwtId,
		string(constants.IssuerClaim):   unit.GetHost(),
		string(constants.SubjectClaim):  grantCtx.Subject,
		string(constants.ScopeClaim):    strings.Join(grantCtx.Scopes, " "),
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantMeta.ExpiresInSecs,
	}
	for k, v := range grantCtx.AdditionalTokenClaims {
		claims[k] = v
	}

	jwk, _ := unit.GetPrivateKey(maker.SigningKeyId)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", maker.SigningKeyId),
	)

	accessToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return Token{
		Id:     jwtId,
		Format: constants.JWT,
		Value:  accessToken,
	}
}

//---------------------------------------- Grant Model ----------------------------------------//

type GrantModel struct {
	Meta       GrantMetaInfo
	TokenMaker AccessTokenMaker
}

func (grantModel GrantModel) generateHalfHashClaim(claimValue string) string {
	jwk, _ := unit.GetPrivateKey(grantModel.Meta.OpenIdKeyId)
	var hash hash.Hash
	switch jose.SignatureAlgorithm(jwk.Algorithm) {
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

func (grantModel GrantModel) GenerateIdToken(grantCtx GrantContext) string {
	jwk, _ := unit.GetPrivateKey(grantModel.Meta.OpenIdKeyId)
	timestampNow := unit.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		string(constants.IssuerClaim):   unit.GetHost(),
		string(constants.SubjectClaim):  grantCtx.Subject,
		string(constants.AudienceClaim): grantCtx.ClientId,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantModel.Meta.ExpiresInSecs,
	}

	if grantCtx.Nonce != "" {
		claims[string(constants.NonceClaim)] = grantCtx.Nonce
	}

	if grantCtx.AccessToken != "" {
		claims[string(constants.AccessTokenHashClaim)] = grantModel.generateHalfHashClaim(grantCtx.AccessToken)
	}

	if grantCtx.AuthorizationCode != "" {
		claims[string(constants.AuthorizationCodeHashClaim)] = grantModel.generateHalfHashClaim(grantCtx.AuthorizationCode)
	}

	if grantCtx.State != "" {
		claims[string(constants.StateHashClaim)] = grantModel.generateHalfHashClaim(grantCtx.State)
	}

	for k, v := range grantCtx.AdditionalIdTokenClaims {
		claims[k] = v
	}

	// Sign the ID token.
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", grantModel.Meta.OpenIdKeyId),
	)
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return idToken
}

func (grantModel GrantModel) GenerateGrantSession(grantCtx GrantContext) GrantSession {
	token := grantModel.TokenMaker.MakeToken(grantModel.Meta, grantCtx)
	grantSession := GrantSession{
		Id:                      uuid.NewString(),
		TokenId:                 token.Id,
		GrantModelId:            grantModel.Meta.Id,
		Token:                   token.Value,
		TokenFormat:             token.Format,
		ExpiresInSecs:           grantModel.Meta.ExpiresInSecs,
		CreatedAtTimestamp:      unit.GetTimestampNow(),
		Subject:                 grantCtx.Subject,
		ClientId:                grantCtx.ClientId,
		Scopes:                  grantCtx.Scopes,
		Nonce:                   grantCtx.Nonce,
		AdditionalTokenClaims:   grantCtx.AdditionalTokenClaims,
		AdditionalIdTokenClaims: grantCtx.AdditionalIdTokenClaims,
	}

	if grantModel.shouldGenerateRefreshToken(grantCtx) {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.RefreshTokenExpiresIn = grantModel.Meta.RefreshLifetimeSecs
	}

	if grantModel.shouldGenerateIdToken(grantCtx) {
		grantSession.IdToken = grantModel.GenerateIdToken(grantCtx)
	}

	return grantSession
}

func (grantModel GrantModel) shouldGenerateRefreshToken(grantCtx GrantContext) bool {
	// There is no need to create a refresh token for the client credentials grant since no user consent is needed.
	return grantCtx.GrantType != constants.ClientCredentialsGrant && grantModel.Meta.IsRefreshable
}

func (grantModel GrantModel) shouldGenerateIdToken(grantCtx GrantContext) bool {
	return unit.Contains(grantCtx.Scopes, []string{constants.OpenIdScope})
}
