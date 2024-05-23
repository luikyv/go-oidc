package models

import (
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantSession struct {
	Id                      string `json:"id"`
	JwkThumbprint           string
	TokenId                 string `json:"token_id"`
	Token                   string
	TokenType               constants.TokenType
	TokenFormat             constants.TokenFormat `json:"token_format"`
	IdToken                 string
	RefreshToken            string            `json:"refresh_token"`
	ExpiresInSecs           int               `json:"expires_in_secs"`
	RefreshTokenExpiresIn   int               `json:"refresh_token_expires_in_secs"`
	CreatedAtTimestamp      int               `json:"created_at"`
	RenewedAtTimestamp      int               `json:"updated_at"`
	Subject                 string            `json:"sub"`
	ClientId                string            `json:"client_id"`
	Scopes                  string            `json:"scope"`
	Nonce                   string            `json:"nonce"`
	AdditionalTokenClaims   map[string]string `json:"additional_token_claims"`
	AdditionalIdTokenClaims map[string]string `json:"additional_id_token_claims"`
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return unit.GetTimestampNow() > grantSession.CreatedAtTimestamp+grantSession.RefreshTokenExpiresIn
}

func (grantSession GrantSession) IsExpired() bool {
	return unit.GetTimestampNow() > grantSession.RenewedAtTimestamp+grantSession.ExpiresInSecs
}

func (grantSession GrantSession) ShouldSave() bool {
	// TODO: implement this.
	return true
}
