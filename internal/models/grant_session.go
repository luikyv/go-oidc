package models

import (
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/unit"
)

type GrantSession struct {
	Id                          string `json:"id"`
	JwkThumbprint               string `json:"jwk_thumbprint"`
	ClientCertificateThumbprint string `json:"certificate_thumbprint"`
	TokenId                     string `json:"token_id"`
	RefreshToken                string `json:"refresh_token"`
	LastTokenIssuedAtTimestamp  int    `json:"last_token_issued_at"`
	CreatedAtTimestamp          int    `json:"created_at"`
	ExpiresAtTimestamp          int    `json:"expires_at"`
	ActiveScopes                string `json:"active_scopes"`
	GrantOptions
}

func NewGrantSession(grantOptions GrantOptions, token Token) GrantSession {
	timestampNow := unit.GetTimestampNow()
	return GrantSession{
		Id:                          uuid.New().String(),
		TokenId:                     token.Id,
		JwkThumbprint:               token.JwkThumbprint,
		ClientCertificateThumbprint: token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.TokenExpiresInSecs,
		ActiveScopes:                grantOptions.GrantedScopes,
		GrantOptions:                grantOptions,
	}
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return unit.GetTimestampNow() > grantSession.ExpiresAtTimestamp
}

func (grantSession GrantSession) HasLastTokenExpired() bool {
	return unit.GetTimestampNow() > grantSession.LastTokenIssuedAtTimestamp+grantSession.TokenExpiresInSecs
}
