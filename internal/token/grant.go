package token

import (
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func NewGrantSession(grantOptions goidc.GrantOptions, token Token) *goidc.GrantSession {
	timestampNow := goidc.TimestampNow()
	return &goidc.GrantSession{
		ID:                          uuid.New().String(),
		TokenID:                     token.ID,
		JWKThumbprint:               token.JWKThumbprint,
		ClientCertificateThumbprint: token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.TokenLifetimeSecs,
		ActiveScopes:                grantOptions.GrantedScopes,
		GrantOptions:                grantOptions,
	}
}
