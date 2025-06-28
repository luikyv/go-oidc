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
	ID string `json:"id"`
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
	// StepID is the identifier of the current step in a multi-step
	// authentication policy. It is used only when such a policy is in effect.
	StepID string `json:"step_id,omitempty"`

	// GrantedScopes is the scopes the client will be granted access once the
	// access token is generated.
	GrantedScopes string `json:"granted_scopes,omitempty"`
	// GrantedAuthDetails is the authorization details the client will be granted
	// access once the access token is generated.
	GrantedAuthDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty"`
	GrantedResources   Resources             `json:"granted_resources,omitempty"`

	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// ClientCertThumbprint contains the thumbprint of the certificate used by
	// the client to generate the token.
	ClientCertThumbprint string `json:"client_cert_thumbprint,omitempty"`

	// Storage allows storing additional information between interactions.
	Storage                  map[string]any `json:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty"`
	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty"`
	ExpiresAtTimestamp       int            `json:"expires_at"`
	CreatedAtTimestamp       int            `json:"created_at"`
	IDTokenHintClaims        map[string]any `json:"id_token_hint_claims,omitempty"`
	AuthorizationParameters
}

// SetUserID sets the subject in the authentication session.
func (s *AuthnSession) SetUserID(userID string) {
	s.Subject = userID
}

func (s *AuthnSession) StoreParameter(key string, value any) {
	if s.Storage == nil {
		s.Storage = make(map[string]any)
	}
	s.Storage[key] = value
}

func (s *AuthnSession) StoredParameter(key string) any {
	return s.Storage[key]
}

func (s *AuthnSession) SetTokenClaim(claim string, value any) {
	if s.AdditionalTokenClaims == nil {
		s.AdditionalTokenClaims = make(map[string]any)
	}
	s.AdditionalTokenClaims[claim] = value
}

func (s *AuthnSession) SetIDTokenClaimACR(acr ACR) {
	s.SetIDTokenClaim(ClaimACR, acr)
}

func (s *AuthnSession) SetIDTokenClaimAuthTime(authTime int) {
	s.SetIDTokenClaim(ClaimAuthTime, authTime)
}

func (s *AuthnSession) SetIDTokenClaimAMR(amrs ...AMR) {
	s.SetIDTokenClaim(ClaimAMR, amrs)
}

// SetIDTokenClaim sets a claim that will be accessible in the ID token.
func (s *AuthnSession) SetIDTokenClaim(claim string, value any) {
	if s.AdditionalIDTokenClaims == nil {
		s.AdditionalIDTokenClaims = make(map[string]any)
	}
	s.AdditionalIDTokenClaims[claim] = value
}

func (s *AuthnSession) SetUserInfoClaimACR(acr ACR) {
	s.SetUserInfoClaim(ClaimACR, acr)
}

func (s *AuthnSession) SetUserInfoClaimAuthTime(authTime int) {
	s.SetUserInfoClaim(ClaimAuthTime, authTime)
}

func (s *AuthnSession) SetUserInfoClaimAMR(amrs ...AMR) {
	s.SetUserInfoClaim(ClaimAMR, amrs)
}

// SetUserInfoClaim sets a claim that will be accessible via the user info endpoint.
func (s *AuthnSession) SetUserInfoClaim(claim string, value any) {
	if s.AdditionalUserInfoClaims == nil {
		s.AdditionalUserInfoClaims = make(map[string]any)
	}
	s.AdditionalUserInfoClaims[claim] = value
}

// GrantScopes sets the scopes the client will have access to.
func (s *AuthnSession) GrantScopes(scopes string) {
	s.GrantedScopes = scopes
}

// GrantAuthorizationDetails sets the authorization details the client will have
// permissions to use.
// This will only have effect if support for authorization details is enabled.
func (s *AuthnSession) GrantAuthorizationDetails(authDetails []AuthorizationDetail) {
	s.GrantedAuthDetails = authDetails
}

func (s *AuthnSession) GrantResources(resources []string) {
	s.GrantedResources = resources
}

func (s *AuthnSession) IsExpired() bool {
	return timeutil.TimestampNow() >= s.ExpiresAtTimestamp
}
