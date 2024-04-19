package models

import (
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

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
	KeyId string
}

func (maker JWTTokenMaker) MakeToken(grantMeta GrantMetaInfo, grantCtx GrantContext) Token {
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenId):  jwtId,
		string(constants.Issuer):   grantMeta.Issuer,
		string(constants.Subject):  grantCtx.Subject,
		string(constants.Scope):    strings.Join(grantCtx.Scopes, " "),
		string(constants.IssuedAt): timestampNow,
		string(constants.Expiry):   timestampNow + grantMeta.ExpiresInSecs,
	}
	for k, v := range grantCtx.AdditionalTokenClaims {
		claims[k] = v
	}

	jwk, _ := unit.GetPrivateKey(maker.KeyId)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", maker.KeyId),
	)

	accessToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return Token{
		Id:     jwtId,
		Format: constants.JWT,
		Value:  accessToken,
	}
}

type GrantMetaInfo struct {
	Id                  string
	Issuer              string
	ExpiresInSecs       int
	IsRefreshable       bool
	RefreshLifetimeSecs int
	OpenIdKeyId         string
}

//---------------------------------------- Grant Model ----------------------------------------//

type GrantModel struct {
	Meta       GrantMetaInfo
	TokenMaker AccessTokenMaker
}

func (grantModel GrantModel) GenerateIdToken(grantCtx GrantContext) string {
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.Issuer):   grantModel.Meta.Issuer,
		string(constants.Subject):  grantCtx.Subject,
		string(constants.Audience): grantCtx.ClientId,
		string(constants.IssuedAt): timestampNow,
		string(constants.Expiry):   timestampNow + grantModel.Meta.ExpiresInSecs,
	}
	if grantCtx.Nonce != "" {
		claims[string(constants.Nonce)] = grantCtx.Nonce
	}
	for k, v := range grantCtx.AdditionalIdTokenClaims {
		claims[k] = v
	}

	jwk, _ := unit.GetPrivateKey(grantModel.Meta.OpenIdKeyId)
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

	if grantCtx.GrantType != constants.ClientCredentials && grantModel.Meta.IsRefreshable {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.RefreshTokenExpiresIn = grantModel.Meta.RefreshLifetimeSecs
	}

	if unit.Contains(grantCtx.Scopes, []string{constants.OpenIdScope}) {
		grantSession.IdToken = grantModel.GenerateIdToken(grantCtx)
	}

	return grantSession
}
