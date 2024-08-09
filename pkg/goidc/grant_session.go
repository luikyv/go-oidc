package goidc

import (
	"context"
	"time"
)

type GrantSessionManager interface {
	Save(ctx context.Context, grantSession *GrantSession) error
	GetByTokenID(ctx context.Context, tokenID string) (*GrantSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*GrantSession, error)
	Delete(ctx context.Context, id string) error
}

type GrantSession struct {
	ID                          string                `json:"id"`
	JWKThumbprint               string                `json:"jwk_thumbprint,omitempty"`
	ClientCertificateThumbprint string                `json:"certificate_thumbprint,omitempty"`
	TokenID                     string                `json:"token_id"`
	RefreshToken                string                `json:"refresh_token,omitempty"`
	LastTokenIssuedAtTimestamp  int64                 `json:"last_token_issued_at"`
	CreatedAtTimestamp          int64                 `json:"created_at"`
	ExpiresAtTimestamp          int64                 `json:"expires_at"`
	ActiveScopes                string                `json:"active_scopes"`
	GrantType                   GrantType             `json:"grant_type"`
	Subject                     string                `json:"sub"`
	ClientID                    string                `json:"client_id"`
	GrantedScopes               string                `json:"granted_scopes"`
	GrantedAuthorizationDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty"`
	AdditionalIDTokenClaims     map[string]any        `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims    map[string]any        `json:"additional_user_info_claims,omitempty"`
	TokenOptions
}

func (g *GrantSession) IsExpired() bool {
	return time.Now().Unix() > g.ExpiresAtTimestamp
}

func (g *GrantSession) HasLastTokenExpired() bool {
	return time.Now().Unix() > g.LastTokenIssuedAtTimestamp+g.TokenLifetimeSecs
}
