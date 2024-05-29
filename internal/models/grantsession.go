package models

import (
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
)

type GrantSession struct {
	Id                        string `json:"id"`
	JwkThumbprint             string `json:"jwk_thumbprint"`
	TokenId                   string `json:"token_id"`
	RefreshToken              string `json:"refresh_token"`
	RefreshTokenExpiresInSecs int    `json:"refresh_token_expires_in_secs"`
	RenewedAtTimestamp        int    `json:"updated_at"`
	CreatedAtTimestamp        int    `json:"created_at"`
	GrantOptions
}

func NewGrantSession(grantOptions GrantOptions, token Token) GrantSession {
	timestampNow := unit.GetTimestampNow()
	return GrantSession{
		Id:                 uuid.New().String(),
		TokenId:            token.Id,
		JwkThumbprint:      token.JwkThumbprint,
		CreatedAtTimestamp: timestampNow,
		RenewedAtTimestamp: timestampNow,
		GrantOptions:       grantOptions,
	}
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return unit.GetTimestampNow() > grantSession.CreatedAtTimestamp+grantSession.RefreshTokenExpiresInSecs
}

func (grantSession GrantSession) IsExpired() bool {
	return unit.GetTimestampNow() > grantSession.RenewedAtTimestamp+grantSession.ExpiresInSecs
}
