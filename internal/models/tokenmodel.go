package models

import (
	"github.com/luikymagno/auth-server/internal/unit"
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

type OpaqueTokenModel struct {
	TokenLength int
	BaseTokenModel
}

func (model OpaqueTokenModel) ToOutput() TokenModelOut {
	return TokenModelOut{}
}

func (model OpaqueTokenModel) GenerateToken(basicInfo TokenContextInfo) Token {
	tokenString := unit.GenerateRandomString(model.TokenLength, model.TokenLength)
	token := Token{
		Id:                 tokenString,
		TokenModelId:       model.Id,
		TokenString:        tokenString,
		ExpiresInSecs:      model.ExpiresInSecs,
		CreatedAtTimestamp: unit.GetTimestampNow(),
		TokenContextInfo:   basicInfo,
	}
	if model.IsRefreshable {
		token.RefreshToken = unit.GenerateRefreshToken()
	}
	return token
}

type TokenModelIn struct{}

func (model TokenModelIn) ToInternal() TokenModel {
	return OpaqueTokenModel{}
}
