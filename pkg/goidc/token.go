package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// TokenManager contains all the logic needed to manage access tokens.
type TokenManager interface {
	Save(context.Context, *Token) error
	Token(context.Context, string) (*Token, error)
	Delete(context.Context, string) error
	// DeleteByGrantID deletes all tokens associated with the given grant
	// session ID. This is used for cascade revocation when a grant is revoked.
	DeleteByGrantID(context.Context, string) error
}

// Token represents an access token issued under a grant session.
// Each token has its own lifecycle and active fields snapshotted at issuance.
type Token struct {
	ID                 string             `json:"id"`
	GrantID            string             `json:"grant_id"`
	ClientID           string             `json:"client_id"`
	Subject            string             `json:"sub"`
	CreatedAtTimestamp int                `json:"created_at"`
	ExpiresAtTimestamp int                `json:"expires_at"`
	Format             TokenFormat        `json:"format"`
	Type               TokenType          `json:"type"`
	SigAlg             SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	Scopes             string             `json:"scopes"`
	AuthDetails        []AuthDetail       `json:"auth_details,omitempty"`
	Resources          Resources          `json:"resources,omitempty"`
	JWKThumbprint      string             `json:"jwk_thumbprint,omitempty"`
	CertThumbprint     string             `json:"cert_thumbprint,omitempty"`
}

// LifetimeSecs returns the token's total lifetime in seconds.
func (t *Token) LifetimeSecs() int {
	return t.ExpiresAtTimestamp - t.CreatedAtTimestamp
}

// IsExpired returns whether the token has expired.
func (t *Token) IsExpired() bool {
	return timeutil.TimestampNow() >= t.ExpiresAtTimestamp
}

type HandleTokenFunc func(context.Context, *Token, *Grant) error
