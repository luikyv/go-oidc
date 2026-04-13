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
	// SessionByAuthCode fetches an authn session by the code created during the
	// authorization code flow.
	// If authorization code is not enabled, this function can be left empty.
	SessionByAuthCode(ctx context.Context, authorizationCode string) (*AuthnSession, error)
	// SessionByPushedAuthReqID fetches an authn session by the request URI created
	// during PAR.
	// If PAR is not enabled, this function can be left empty.
	SessionByPushedAuthReqID(ctx context.Context, id string) (*AuthnSession, error)
	// SessionByCIBAAuthID fetches an authn session by the auth request ID created
	// during CIBA.
	// If CIBA is not enabled, this function can be left empty.
	SessionByCIBAAuthID(ctx context.Context, id string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}

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
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	// PushedAuthReqID is the id generated during /par used to fetch the session
	// during calls to /authorize.
	//
	// This value will be returned as the request_uri of the /par response.
	PushedAuthReqID string `json:"pushed_auth_req_id,omitempty"`
	// CallbackID is the id used to fetch the authentication session after user
	// interaction during calls to the callback endpoint.
	CallbackID string `json:"callback_id,omitempty"`
	CIBAAuthID string `json:"ciba_auth_req_id,omitempty"`
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
