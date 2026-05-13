package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// Token represents an access token issued under a grant session.
// Each token has its own lifecycle and active fields snapshotted at issuance.
type Token struct {
	ID             string             `json:"id"`
	GrantID        string             `json:"grant_id"`
	ClientID       string             `json:"client_id"`
	Subject        string             `json:"sub"`
	CreatedAt      int                `json:"created_at"`
	ExpiresAt      int                `json:"expires_at"`
	Format         TokenFormat        `json:"format"`
	Type           TokenType          `json:"type"`
	SigAlg         SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	Scopes         string             `json:"scopes"`
	AuthDetails    []AuthDetail       `json:"auth_details,omitempty"`
	Resources      Resources          `json:"resources,omitempty"`
	JWKThumbprint  string             `json:"jwk_thumbprint,omitempty"`
	CertThumbprint string             `json:"cert_thumbprint,omitempty"`
}

// LifetimeSecs returns the token's total lifetime in seconds.
func (t *Token) LifetimeSecs() int {
	return t.ExpiresAt - t.CreatedAt
}

// IsExpired returns whether the token has expired.
func (t *Token) IsExpired() bool {
	return timeutil.TimestampNow() >= t.ExpiresAt
}

type HandleTokenFunc func(context.Context, *Token, *Grant) error
