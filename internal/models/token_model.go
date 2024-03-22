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
	token := unit.GenerateRandomString(model.TokenLength, model.TokenLength)
	return Token{
		Id:                 token,
		TokenString:        token,
		ExpiresInSecs:      model.ExpiresInSecs,
		CreatedAtTimestamp: unit.GetTimestampNow(),
		TokenContextInfo:   basicInfo,
	}
}

type TokenModelIn struct{}

func (model TokenModelIn) ToInternal() TokenModel {
	return OpaqueTokenModel{}
}
