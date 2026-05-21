package goidc

import (
	"context"
)

// Grant represents the granted access an entity (a user or the client itself) gave to a client.
type Grant struct {
	ID        string `json:"id"`
	CreatedAt int    `json:"created_at"`
	RevokedAt int    `json:"revoked_at,omitempty"`
	Subject   string `json:"sub"`
	ClientID  string `json:"client_id"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	Username    string       `json:"username,omitempty"`
	Scopes      string       `json:"scopes,omitempty"`
	AuthDetails []AuthDetail `json:"auth_details,omitempty"`
	Resources   Resources    `json:"resources,omitempty"`

	// RefreshToken, if present, is the plain text refresh token issued for this grant.
	// Note: For security reasons, it is strongly recommended to encrypt this value before storing it in a database.
	RefreshToken string `json:"refresh_token,omitempty"`
	// RefreshTokenExpiresAt stores the expiry deadline of the refresh token
	// issued for this grant.
	RefreshTokenExpiresAt int                     `json:"refresh_token_expires_at,omitempty"`
	AuthParams            AuthorizationParameters `json:"auth_params,omitzero"`
	// AuthCode is populated when the grant is issued from the authorization
	// code flow. It is the code later redeemed at the token endpoint.
	AuthCode string `json:"auth_code,omitempty"`
	// AuthCodeExpiresAt stores the original authorization code expiry deadline,
	// so redemption remains bounded by that window independently of grant
	// creation time.
	AuthCodeExpiresAt int `json:"auth_code_expires_at,omitempty"`
	// AuthCodeConsumedAt is populated once the authorization code has been
	// successfully redeemed, so reuse can be detected.
	AuthCodeConsumedAt int `json:"auth_code_consumed_at,omitempty"`
	// PreAuthCode is populated for pre-authorized code flows.
	PreAuthCode string `json:"pre_auth_code,omitempty"`
	// AuthReqID is populated when a CIBA request is approved and turned into a
	// grant.
	AuthReqID string `json:"auth_req_id,omitempty"`
	// AuthReqIDExpiresAt stores the original auth_req_id expiry deadline from
	// the CIBA acknowledgement, so redemption remains bounded by that window
	// even though the grant is created later.
	AuthReqIDExpiresAt int `json:"auth_req_id_expires_at,omitempty"`
	// AuthReqIDConsumedAt is populated once the auth_req_id has been redeemed
	// at the token endpoint, so reuse can be detected.
	AuthReqIDConsumedAt int `json:"auth_req_id_consumed_at,omitempty"`
	// DeviceCode is populated when a device authorization request is approved
	// and turned into a grant.
	DeviceCode string `json:"device_code,omitempty"`
	// DeviceCodeExpiresAt stores the original device_code expiry deadline from
	// the device authorization response, so redemption remains bounded by that
	// window even after the grant is created.
	DeviceCodeExpiresAt int `json:"device_code_expires_at,omitempty"`
	// DeviceCodeConsumedAt is populated once the device code has been redeemed
	// at the token endpoint, so reuse can be detected.
	DeviceCodeConsumedAt int `json:"device_code_consumed_at,omitempty"`
	// JWKThumbprint stores the thumbprint of the JWK provided via DPoP.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// CertThumbprint contains the thumbprint of the certificate used to generate the token.
	CertThumbprint string `json:"cert_thumbprint,omitempty"`
	// Store allows storing custom data within the grant.
	Store map[string]any `json:"store,omitempty"`
}

type HandleGrantFunc func(context.Context, *Grant) error
