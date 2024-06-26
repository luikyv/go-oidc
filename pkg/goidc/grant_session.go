package goidc

type GrantSession struct {
	Id                          string `json:"id" bson:"_id"`
	JwkThumbprint               string `json:"jwk_thumbprint,omitempty" bson:"jwk_thumbprint,omitempty"`
	ClientCertificateThumbprint string `json:"certificate_thumbprint,omitempty" bson:"certificate_thumbprint,omitempty"`
	TokenId                     string `json:"token_id" bson:"token_id"`
	RefreshToken                string `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
	LastTokenIssuedAtTimestamp  int    `json:"last_token_issued_at" bson:"last_token_issued_at"`
	CreatedAtTimestamp          int    `json:"created_at" bson:"created_at"` // TODO: remove this.
	ExpiresAtTimestamp          int    `json:"expires_at" bson:"expires_at"`
	ActiveScopes                string `json:"active_scopes" bson:"active_scopes"`
	GrantOptions                `bson:"inline"`
}

func (grantSession GrantSession) IsRefreshSessionExpired() bool {
	return GetTimestampNow() > grantSession.ExpiresAtTimestamp
}

func (grantSession GrantSession) HasLastTokenExpired() bool {
	return GetTimestampNow() > grantSession.LastTokenIssuedAtTimestamp+grantSession.TokenLifetimeSecs
}
