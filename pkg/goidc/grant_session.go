package goidc

type GrantSession struct {
	ID                          string `json:"id" bson:"_id"`
	JWKThumbprint               string `json:"jwk_thumbprint,omitempty" bson:"jwk_thumbprint,omitempty"`
	ClientCertificateThumbprint string `json:"certificate_thumbprint,omitempty" bson:"certificate_thumbprint,omitempty"`
	TokenID                     string `json:"token_id" bson:"token_id"`
	RefreshToken                string `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
	LastTokenIssuedAtTimestamp  int    `json:"last_token_issued_at" bson:"last_token_issued_at"`
	CreatedAtTimestamp          int    `json:"created_at" bson:"created_at"`
	ExpiresAtTimestamp          int    `json:"expires_at" bson:"expires_at"`
	ActiveScopes                string `json:"active_scopes" bson:"active_scopes"`
	GrantOptions                `bson:"inline"`
}

func (g *GrantSession) IsRefreshSessionExpired() bool {
	return TimestampNow() > g.ExpiresAtTimestamp
}

func (g *GrantSession) HasLastTokenExpired() bool {
	return TimestampNow() > g.LastTokenIssuedAtTimestamp+g.TokenLifetimeSecs
}

func (g *GrantSession) TokenConfirmation() TokenConfirmation {
	return TokenConfirmation{
		JWKThumbprint:               g.JWKThumbprint,
		ClientCertificateThumbprint: g.ClientCertificateThumbprint,
	}
}
