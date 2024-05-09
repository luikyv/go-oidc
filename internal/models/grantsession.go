package models

import (
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantSession struct {
	Id                      string
	JwkThumbprint           string
	GrantModelId            string
	TokenId                 string
	Token                   string
	TokenFormat             constants.TokenFormat
	IdToken                 string
	RefreshToken            string
	ExpiresInSecs           int
	RefreshTokenExpiresIn   int
	CreatedAtTimestamp      int
	Subject                 string
	ClientId                string
	Scopes                  []string
	Nonce                   string
	AdditionalTokenClaims   map[string]string
	AdditionalIdTokenClaims map[string]string
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return unit.GetTimestampNow() > grantSession.CreatedAtTimestamp+grantSession.RefreshTokenExpiresIn
}
