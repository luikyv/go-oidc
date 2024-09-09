package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// GrantSessionManager contains all the logic needed to manage grant sessions.
type GrantSessionManager interface {
	Save(ctx context.Context, grantSession *GrantSession) error
	SessionByTokenID(ctx context.Context, tokenID string) (*GrantSession, error)
	SessionByRefreshToken(ctx context.Context, refreshToken string) (*GrantSession, error)
	Delete(ctx context.Context, id string) error
}

// GrantSession represents the granted access an entity (a user or the client
// itself) gave to a client.
// It holds information about the token issued to a client and about the user
// who granted access.
type GrantSession struct {
	ID string `json:"id"`
	// TokenID is the id of the token issued for this grant.
	TokenID      string `json:"token_id"` // TODO: Think about it. The jti will work for this.
	RefreshToken string `json:"refresh_token,omitempty"`
	// LastTokenExpiresAtTimestamp is the timestamp when the last token issued
	// for this grant was created.
	LastTokenExpiresAtTimestamp int `json:"last_token_expires_at"`
	CreatedAtTimestamp          int `json:"created_at"`
	ExpiresAtTimestamp          int `json:"expires_at"`
	GrantInfo
}

type HandleGrantFunc func(*GrantInfo) error // TODO.

type GrantInfo struct {
	GrantType GrantType `json:"grant_type"`
	Subject   string    `json:"sub"`
	ClientID  string    `json:"client_id"`

	// ActiveScopes is a sub set of the granted scopes the current access token
	// give permissions to.
	// Most of the times, GrantedScopes and ActiveScopes are equal.
	// This is not true when a client refreshes a token asking less permissions
	// than it was granted.
	// In this case, only the scopes requested will be active.
	ActiveScopes string `json:"active_scopes"`
	// GrantedScopes are all the scopes a client was given permission to.
	GrantedScopes string `json:"granted_scopes"`
	// GrantedAuthorizationDetails are all the authorization details a client
	// was given permission to.
	GrantedAuthorizationDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty"`
	ActiveResources             Resources             `json:"active_resources,omitempty"`
	GrantedResources            Resources             `json:"granted_resources,omitempty"`

	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty"`

	// JWKThumbprint is the thumbprint of the JWK informed via DPoP.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// ClientCertThumbprint is the thumbprint of the certificate informed by the
	// client when generating a token.
	ClientCertThumbprint string `json:"certificate_thumbprint,omitempty"`
}

func (g *GrantSession) IsExpired() bool {
	return timeutil.TimestampNow() > g.ExpiresAtTimestamp
}

// HasLastTokenExpired returns whether the last token issued for the grant
// session is expired or not.
func (g *GrantSession) HasLastTokenExpired() bool {
	return timeutil.TimestampNow() > g.LastTokenExpiresAtTimestamp
}
