package models

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantMetaInfo struct {
	Id                  string
	Issuer              string
	ExpiresInSecs       int
	IsRefreshable       bool
	RefreshLifetimeSecs int
	OpenIdPrivateJwk    jose.JSONWebKey
}

//---------------------------------------- Token Makers ----------------------------------------//

type Token struct {
	Id            string
	Format        constants.TokenFormat
	Value         string
	Type          constants.TokenType
	JwkThumbprint string
}

type AccessTokenMaker interface {
	MakeToken(grantMeta GrantMetaInfo, grantOptions GrantOptions) Token
}

type OpaqueTokenMaker struct {
	TokenLength int
}

func (maker OpaqueTokenMaker) MakeToken(grantMeta GrantMetaInfo, grantOptions GrantOptions) Token {
	accessToken := unit.GenerateRandomString(maker.TokenLength, maker.TokenLength)
	tokenType := constants.BearerTokenType
	jkt := ""
	if grantOptions.DpopJwt != "" {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(grantOptions.DpopJwt)
	}
	return Token{
		Id:            accessToken,
		Format:        constants.Opaque,
		Value:         accessToken,
		Type:          tokenType,
		JwkThumbprint: jkt,
	}
}

type JWTTokenMaker struct {
	PrivateJwk jose.JSONWebKey
}

func (maker JWTTokenMaker) MakeToken(grantMeta GrantMetaInfo, grantOptions GrantOptions) Token {
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenIdClaim):  jwtId,
		string(constants.IssuerClaim):   grantMeta.Issuer,
		string(constants.SubjectClaim):  grantOptions.Subject,
		string(constants.ScopeClaim):    strings.Join(grantOptions.Scopes, " "),
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantMeta.ExpiresInSecs,
	}

	tokenType := constants.BearerTokenType
	jkt := ""
	if grantOptions.DpopJwt != "" {
		tokenType = constants.DpopTokenType
		jkt = unit.GenerateJwkThumbprint(grantOptions.DpopJwt)
		claims["cnf"] = map[string]string{
			"jkt": jkt,
		}
	}

	for k, v := range grantOptions.AdditionalTokenClaims {
		claims[k] = v
	}

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(maker.PrivateJwk.Algorithm), Key: maker.PrivateJwk.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", maker.PrivateJwk.KeyID),
	)

	accessToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return Token{
		Id:            jwtId,
		Format:        constants.JWT,
		Value:         accessToken,
		Type:          tokenType,
		JwkThumbprint: jkt,
	}
}

//---------------------------------------- Grant Model ----------------------------------------//

type GrantModel struct {
	Meta       GrantMetaInfo
	TokenMaker AccessTokenMaker
}

func (grantModel GrantModel) generateHalfHashClaim(claimValue string) string {
	var hash hash.Hash
	switch jose.SignatureAlgorithm(grantModel.Meta.OpenIdPrivateJwk.Algorithm) {
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

func (grantModel GrantModel) GenerateIdToken(grantOptions GrantOptions) string {
	timestampNow := unit.GetTimestampNow()

	// Set the token claims.
	claims := map[string]any{
		string(constants.IssuerClaim):   grantModel.Meta.Issuer,
		string(constants.SubjectClaim):  grantOptions.Subject,
		string(constants.AudienceClaim): grantOptions.ClientId,
		string(constants.IssuedAtClaim): timestampNow,
		string(constants.ExpiryClaim):   timestampNow + grantModel.Meta.ExpiresInSecs,
	}

	if grantOptions.Nonce != "" {
		claims[string(constants.NonceClaim)] = grantOptions.Nonce
	}

	if grantOptions.AccessToken != "" {
		claims[string(constants.AccessTokenHashClaim)] = grantModel.generateHalfHashClaim(grantOptions.AccessToken)
	}

	if grantOptions.AuthorizationCode != "" {
		claims[string(constants.AuthorizationCodeHashClaim)] = grantModel.generateHalfHashClaim(grantOptions.AuthorizationCode)
	}

	if grantOptions.State != "" {
		claims[string(constants.StateHashClaim)] = grantModel.generateHalfHashClaim(grantOptions.State)
	}

	for k, v := range grantOptions.AdditionalIdTokenClaims {
		claims[k] = v
	}

	// Sign the ID token.
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(grantModel.Meta.OpenIdPrivateJwk.Algorithm), Key: grantModel.Meta.OpenIdPrivateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", grantModel.Meta.OpenIdPrivateJwk.KeyID),
	)
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return idToken
}

func (grantModel GrantModel) GenerateGrantSession(grantOptions GrantOptions) GrantSession {
	token := grantModel.TokenMaker.MakeToken(grantModel.Meta, grantOptions)
	grantSession := GrantSession{
		Id:                      uuid.NewString(),
		JwkThumbprint:           token.JwkThumbprint,
		TokenId:                 token.Id,
		GrantModelId:            grantModel.Meta.Id,
		Token:                   token.Value,
		TokenFormat:             token.Format,
		TokenType:               token.Type,
		ExpiresInSecs:           grantModel.Meta.ExpiresInSecs,
		CreatedAtTimestamp:      unit.GetTimestampNow(),
		Subject:                 grantOptions.Subject,
		ClientId:                grantOptions.ClientId,
		Scopes:                  grantOptions.Scopes,
		Nonce:                   grantOptions.Nonce,
		AdditionalTokenClaims:   grantOptions.AdditionalTokenClaims,
		AdditionalIdTokenClaims: grantOptions.AdditionalIdTokenClaims,
	}

	if grantModel.shouldGenerateRefreshToken(grantOptions) {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.RefreshTokenExpiresIn = grantModel.Meta.RefreshLifetimeSecs
	}

	if grantModel.shouldGenerateIdToken(grantOptions) {
		grantSession.IdToken = grantModel.GenerateIdToken(grantOptions)
	}

	return grantSession
}

func (grantModel GrantModel) shouldGenerateRefreshToken(grantOptions GrantOptions) bool {
	// There is no need to create a refresh token for the client credentials grant since no user consent is needed.
	return grantOptions.GrantType != constants.ClientCredentialsGrant && grantModel.Meta.IsRefreshable
}

func (grantModel GrantModel) shouldGenerateIdToken(grantOptions GrantOptions) bool {
	return slices.Contains(grantOptions.Scopes, constants.OpenIdScope)
}
