package models

import (
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantSession struct {
	JwkThumbprint             string `json:"jwk_thumbprint"`
	TokenId                   string `json:"token_id"`
	Token                     string
	TokenType                 constants.TokenType
	IdToken                   string
	RefreshToken              string `json:"refresh_token"`
	RefreshTokenExpiresInSecs int    `json:"refresh_token_expires_in_secs"`
	RenewedAtTimestamp        int    `json:"updated_at"`
	GrantOptions
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return unit.GetTimestampNow() > grantSession.CreatedAtTimestamp+grantSession.RefreshTokenExpiresInSecs
}

func (grantSession GrantSession) IsExpired() bool {
	return unit.GetTimestampNow() > grantSession.RenewedAtTimestamp+grantSession.ExpiresInSecs
}
