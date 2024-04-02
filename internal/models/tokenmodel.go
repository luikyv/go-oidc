package models

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
	Jwk JWK
	BaseTokenModel
}

func (model JWTTokenModel) getJWTSigningMethod(signingAlg constants.SigningAlgorithm) jwt.SigningMethod {
	switch signingAlg {
	case constants.HS256:
		return jwt.SigningMethodHS256
	default:
		//TODO: Improve this.
		return jwt.SigningMethodHS256
	}
}

func (tokenModel JWTTokenModel) GenerateToken(basicInfo TokenContextInfo) Token {
	createdAtTimestamp := unit.GetTimestampNow()
	tokenString, _ := jwt.NewWithClaims(
		tokenModel.getJWTSigningMethod(tokenModel.Jwk.SigningAlgorithm),
		jwt.MapClaims{
			"sub":       basicInfo.Subject,
			"client_id": basicInfo.ClientId,
			"scope":     strings.Join(basicInfo.Scopes, " "),
			"exp":       createdAtTimestamp + tokenModel.ExpiresInSecs,
			"iat":       createdAtTimestamp,
		},
	).SignedString([]byte(tokenModel.Jwk.Key))

	token := Token{
		Id:                 uuid.NewString(),
		TokenModelId:       tokenModel.Id,
		TokenString:        tokenString,
		ExpiresInSecs:      tokenModel.ExpiresInSecs,
		CreatedAtTimestamp: createdAtTimestamp,
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
