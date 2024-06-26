package goidc

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

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return GetTimestampNow() > grantSession.ExpiresAtTimestamp
}

func (grantSession GrantSession) HasLastTokenExpired() bool {
	return GetTimestampNow() > grantSession.LastTokenIssuedAtTimestamp+grantSession.TokenExpiresInSecs
}
