package models

import (
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type TokenModelOut struct{}

type TokenModel interface {
	ToOutput() TokenModelOut
	GenerateToken(TokenContextInfo) Token
}

type BaseTokenModel struct {
	Id                  string
	Issuer              string
	ExpiresInSecs       int
	IsRefreshable       bool
	RefreshLifetimeSecs int
}

type TokenModelIn struct{}

func (model TokenModelIn) ToInternal() TokenModel {
	return OpaqueTokenModel{}
}

//---------------------------------------- Opaque ----------------------------------------//

type OpaqueTokenModel struct {
	TokenLength int
	BaseTokenModel
}

func (tokenModel OpaqueTokenModel) GenerateToken(basicInfo TokenContextInfo) Token {
	tokenString := unit.GenerateRandomString(tokenModel.TokenLength, tokenModel.TokenLength)
	token := Token{
		Id:                 tokenString,
		TokenModelId:       tokenModel.Id,
		TokenString:        tokenString,
		ExpiresInSecs:      tokenModel.ExpiresInSecs,
		CreatedAtTimestamp: unit.GetTimestampNow(),
		TokenContextInfo:   basicInfo,
	}
	if tokenModel.IsRefreshable {
		token.RefreshToken = unit.GenerateRefreshToken()
	}

	return token
}

func (model OpaqueTokenModel) ToOutput() TokenModelOut {
	return TokenModelOut{}
}

//---------------------------------------- JWT ----------------------------------------//

type JWTTokenModel struct {
	KeyId string
	BaseTokenModel
}

func (tokenModel JWTTokenModel) GenerateToken(basicInfo TokenContextInfo) Token {
	jti := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenId):  jti,
		string(constants.Issuer):   tokenModel.Issuer,
		string(constants.Subject):  basicInfo.Subject,
		string(constants.Scope):    strings.Join(basicInfo.Scopes, " "),
		string(constants.IssuedAt): timestampNow,
		string(constants.Expiry):   timestampNow + tokenModel.ExpiresInSecs,
	}

	jwk := unit.GetPrivateKey(tokenModel.KeyId)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key}, nil)
	tokenString, _ := jwt.Signed(signer).Claims(claims).Serialize()

	token := Token{
		Id:                 jti,
		TokenModelId:       tokenModel.Id,
		TokenString:        tokenString,
		ExpiresInSecs:      tokenModel.ExpiresInSecs,
		CreatedAtTimestamp: timestampNow,
		TokenContextInfo:   basicInfo,
	}
	if tokenModel.IsRefreshable {
		token.RefreshToken = unit.GenerateRefreshToken()
	}

	return token
}

func (model JWTTokenModel) ToOutput() TokenModelOut {
	return TokenModelOut{}
}
