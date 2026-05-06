package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// AuthnSessionManager contains all the logic needed to manage authentication
// sessions.
type AuthnSessionManager interface {
	Save(ctx context.Context, session *AuthnSession) error
	SessionByCallbackID(ctx context.Context, callbackID string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSessionByAuthCodeFunc func(context.Context, string) (*AuthnSession, error)

type AuthnSessionByPARIDFunc func(context.Context, string) (*AuthnSession, error)

type AuthnSessionByCIBAIDFunc func(context.Context, string) (*AuthnSession, error)

// AuthnSession is a short lived session that holds information about
// authorization requests.
// It can be interacted with so to implement more sophisticated user
// authentication flows.
type AuthnSession struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	// Subject is the user identifier.
	//
	// This value must be informed during the authentication flow.
	Subject string `json:"sub"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	// When set during the authentication flow, it is propagated to the resulting
	// grant and returned in the introspection response.
	Username string `json:"username,omitempty"`
	ClientID string `json:"client_id"`
	// PARID is the id generated during /par used to fetch the session
	// during calls to /authorize.
	//
	// This value will be returned as the request_uri of the /par response.
	PARID string `json:"par_id,omitempty"`
	// CallbackID is the id used to fetch the authentication session after user
	// interaction during calls to the callback endpoint.
	CallbackID string `json:"callback_id,omitempty"`
	CIBAID     string `json:"ciba_id,omitempty"`
	AuthCode   string `json:"auth_code,omitempty"`
	// PolicyID is the id of the autentication policy used to authenticate
	// the user.
	PolicyID string `json:"policy_id,omitempty"`

	// GrantedScopes is the scopes the client will be granted access once the
	// access token is generated.
	GrantedScopes string `json:"granted_scopes,omitempty"`
	// GrantedAuthDetails is the authorization details the client will be granted
	// access once the access token is generated.
	GrantedAuthDetails []AuthDetail `json:"granted_authorization_details,omitempty"`
	GrantedResources   Resources    `json:"granted_resources,omitempty"`

	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// ClientCertThumbprint contains the thumbprint of the certificate used by
	// the client to generate the token.
	ClientCertThumbprint string `json:"client_cert_thumbprint,omitempty"`

	// Store allows storing additional information between interactions.
	Store              map[string]any `json:"store,omitempty"`
	ExpiresAtTimestamp int            `json:"expires_at"`
	CreatedAtTimestamp int            `json:"created_at"`
	IDTokenHintClaims  map[string]any `json:"id_token_hint_claims,omitempty"`
	VCInfo             *struct {
		Issuer           string              `json:"issuer"`
		ConfigurationIDs []VCConfigurationID `json:"configuration_ids"`
	} `json:"vc_info,omitempty"`
	AuthorizationParameters
}

func (s *AuthnSession) IsExpired() bool {
	return timeutil.TimestampNow() >= s.ExpiresAtTimestamp
}
