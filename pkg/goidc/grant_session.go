package goidc

import (
	"context"
	"net/http"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// GrantSessionManager contains all the logic needed to manage grant sessions.
type GrantSessionManager interface {
	Save(context.Context, *GrantSession) error
	SessionByTokenID(context.Context, string) (*GrantSession, error)
	SessionByRefreshToken(context.Context, string) (*GrantSession, error)
	Delete(ctx context.Context, id string) error
	DeleteByAuthorizationCode(context.Context, string) error
}

// GrantSession represents the granted access an entity (a user or the client
// itself) gave to a client.
// It holds information about the token issued to a client and about the user
// who granted access.
type GrantSession struct {
	ID string `json:"id"`
	// TokenID is the id of the token issued for this grant.
	TokenID      string `json:"token_id"` // FIXME: The jti will work for this.
	RefreshToken string `json:"refresh_token,omitempty"`
	// LastTokenExpiresAtTimestamp is the timestamp when the last token issued
	// for this grant was created.
	LastTokenExpiresAtTimestamp int `json:"last_token_expires_at"`
	CreatedAtTimestamp          int `json:"created_at"`
	ExpiresAtTimestamp          int `json:"expires_at"`
	// AuthorizationCode is the authorization code used to generate this grant
	// session in case of authorization code grant type.
	AuthorizationCode string `json:"authorization_code,omitempty"`
	GrantInfo
}

type HandleGrantFunc func(*http.Request, *GrantInfo) error

// GrantInfo contains the information assigned during token issuance.
//
//   - For authorization_code and refresh_token grant types:
//     Granted information represents what the user authorized. Active information
//     is either the subset requested by the client during the token request or
//     the full granted information if no specific subset was requested.
//
//   - For client_credentials and jwt_bearer grant types:
//     Both granted and active information reflect exactly what the client
//     requested in the token request.
//
// Additional validations can be performed using a [HandleGrantFunc].
type GrantInfo struct {
	GrantType GrantType `json:"grant_type"`
	// Subject is the ID of the user or client associated with the grant.
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`

	// ActiveScopes represents the subset of GrantedScopes that are active
	// for the current access token.
	// Typically, ActiveScopes are equals to GrantedScopes, unless the token
	// request asks fewer scopes than initially granted.
	ActiveScopes string `json:"active_scopes"`
	// GrantedScopes lists all scopes the client has permission to access.
	GrantedScopes string `json:"granted_scopes"`
	// ActiveAuthDetails contains the subset of GrantedAuthDetails currently
	// active for this access token.
	ActiveAuthDetails []AuthorizationDetail `json:"active_auth_details,omitempty"`
	// GrantedAuthDetails holds all authorization details assigned to the client.
	GrantedAuthDetails []AuthorizationDetail `json:"granted_auth_details,omitempty"`
	// ActiveResources are the specific resources the current token can be used
	// with.
	ActiveResources Resources `json:"active_resources,omitempty"`
	// GrantedResources lists all resources the client was authorized to interact.
	GrantedResources Resources `json:"granted_resources,omitempty"`

	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty"`

	// JWKThumbprint stores the thumbprint of the JWK provided via DPoP.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// ClientCertThumbprint contains the thumbprint of the certificate used by
	// the client to generate the token.
	ClientCertThumbprint string `json:"certificate_thumbprint,omitempty"`

	// Store allows storing custom data within the grant session.
	Store map[string]any `json:"store"`
}

func (g *GrantSession) IsExpired() bool {
	return timeutil.TimestampNow() >= g.ExpiresAtTimestamp
}

// HasLastTokenExpired returns whether the last token issued for the grant
// session is expired or not.
func (g *GrantSession) HasLastTokenExpired() bool {
	return timeutil.TimestampNow() >= g.LastTokenExpiresAtTimestamp
}
