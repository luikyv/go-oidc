package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// Grant represents the granted access an entity (a user or the client itself) gave to a client.
type Grant struct {
	ID string `json:"id"`
	// RefreshToken, if present, is the plain text refresh token issued for this grant.
	// Note: For security reasons, it is strongly recommended to encrypt this value before storing it in a database.
	RefreshToken string `json:"refresh_token,omitempty"`
	// TODO: Refresh token expires at.
	CreatedAt int    `json:"created_at"`
	ExpiresAt int    `json:"expires_at"`
	Subject   string `json:"sub"`
	ClientID  string `json:"client_id"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	Username    string       `json:"username,omitempty"`
	Scopes      string       `json:"scopes,omitempty"`
	AuthDetails []AuthDetail `json:"auth_details,omitempty"`
	Resources   Resources    `json:"resources,omitempty"`

	AuthParams           AuthorizationParameters `json:"auth_params,omitzero"`
	AuthCode             string                  `json:"auth_code,omitempty"`
	AuthCodeConsumedAt   int                     `json:"auth_code_consumed_at,omitempty"`
	PreAuthCode          string                  `json:"pre_aut_code,omitempty"`
	AuthReqID            string                  `json:"auth_req_id,omitempty"`
	AuthReqIDConsumedAt  int                     `json:"auth_req_id_consumed_at,omitempty"`
	DeviceCode           string                  `json:"device_code,omitempty"`
	DeviceCodeConsumedAt int                     `json:"device_code_consumed_at,omitempty"`

	// JWKThumbprint stores the thumbprint of the JWK provided via DPoP.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// CertThumbprint contains the thumbprint of the certificate used to generate the token.
	CertThumbprint string `json:"cert_thumbprint,omitempty"`

	// Store allows storing custom data within the grant.
	Store map[string]any `json:"store,omitempty"`
}

func (g *Grant) IsExpired() bool {
	return g.ExpiresAt > 0 && timeutil.TimestampNow() >= g.ExpiresAt
}

type HandleGrantFunc func(context.Context, *Grant) error
