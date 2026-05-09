package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

type GrantManager interface {
	Save(context.Context, *Grant) error
	Grant(context.Context, string) (*Grant, error)
	Delete(context.Context, string) error
	GrantByRefreshToken(context.Context, string) (*Grant, error)
	DeleteByAuthCode(context.Context, string) error
	DeleteByDeviceCode(context.Context, string) error
}

// Grant represents the granted access an entity (a user or the client itself) gave to a client.
type Grant struct {
	ID string `json:"id"`
	// RefreshToken, if present, is the plain text refresh token issued for this grant.
	// Note: For security reasons, it is strongly recommended to encrypt this value before storing it in a database.
	RefreshToken       string `json:"refresh_token,omitempty"`
	CreatedAtTimestamp int    `json:"created_at"`
	ExpiresAtTimestamp int    `json:"expires_at"`
	// AuthCode is the authorization code used to generate this grant
	// in case of authorization code grant type.
	AuthCode string `json:"authorization_code,omitempty"`
	// PreAuthCode is the pre-authorized code used to generate this grant
	// in case of pre-authorized code grant type.
	PreAuthCode string `json:"pre_authorized_code,omitempty"`
	DeviceCode  string `json:"device_code,omitempty"`

	Type GrantType `json:"grant_type"`
	// Subject is the ID of the user or client associated with the grant.
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	// Populated via HandleGrantFunc or by resource-owner password grant.
	Username string `json:"username,omitempty"`

	Scopes      string       `json:"scopes"`
	AuthDetails []AuthDetail `json:"auth_details,omitempty"`
	Resources   Resources    `json:"resources,omitempty"`

	// Nonce is the nonce sent by the client in the authorization request.
	// If present, it will be included in the ID token.
	Nonce string `json:"nonce,omitempty"`

	// JWKThumbprint stores the thumbprint of the JWK provided via DPoP.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// CertThumbprint contains the thumbprint of the certificate used to generate the token.
	CertThumbprint string `json:"cert_thumbprint,omitempty"`

	// Store allows storing custom data within the grant.
	Store map[string]any `json:"store,omitempty"`
}

// IsExpired returns whether the grant has expired.
// A zero ExpiresAtTimestamp means the grant never expires.
func (g *Grant) IsExpired() bool {
	return g.ExpiresAtTimestamp > 0 && timeutil.TimestampNow() >= g.ExpiresAtTimestamp
}

type HandleGrantFunc func(context.Context, *Grant) error
