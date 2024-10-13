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
	SessionByAuthorizationCode(ctx context.Context, authorizationCode string) (*AuthnSession, error)
	SessionByReferenceID(ctx context.Context, requestURI string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}

// AuthnSession is a short lived session that holds information about
// authorization requests.
// It can be interacted with so to implement more sophisticated user
// authentication flows.
type AuthnSession struct {
	ID string `json:"id"`
	// ReferenceID is the id generated during /par used to fetch the session
	// during calls to /authorize.
	//
	// This value will be returned as the request_uri of the /par response.
	ReferenceID string `json:"reference_id"`
	// CallbackID is the id used to fetch the authentication session after user
	// interaction during calls to the callback endpoint.
	CallbackID string `json:"callback_id"`
	// PolicyID is the id of the autentication policy used to authenticate
	// the user.
	PolicyID           string `json:"policy_id"`
	ExpiresAtTimestamp int    `json:"expires_at"`
	CreatedAtTimestamp int    `json:"created_at"`
	// Subject is the user identifier.
	//
	// This value must be informed during the authentication flow.
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	// GrantedScopes is the scopes the client will be granted access once the
	// access token is generated.
	GrantedScopes string `json:"granted_scopes"`
	// GrantedAuthDetails is the authorization details the client will be granted
	// access once the access token is generated.
	GrantedAuthDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty"`
	GrantedResources   Resources             `json:"granted_resources,omitempty"`
	AuthorizationCode  string                `json:"authorization_code,omitempty"`
	// ProtectedParameters contains custom parameters sent by PAR.
	ProtectedParameters map[string]any `json:"protected_params,omitempty"`
	// Store allows storing information between user interactions.
	Store                    map[string]any `json:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty"`
	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty"`
	AuthorizationParameters
	Error string `json:"-"`
}

// SetUserID sets the subject in the authentication session.
func (s *AuthnSession) SetUserID(userID string) {
	s.Subject = userID
}

func (s *AuthnSession) StoreParameter(key string, value any) {
	if s.Store == nil {
		s.Store = make(map[string]any)
	}
	s.Store[key] = value
}

func (s *AuthnSession) Parameter(key string) any {
	return s.Store[key]
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

// SetError defines the error that will be informed to the client once the
// authentication flow results in failure.
func (s *AuthnSession) SetError(err string) {
	s.Error = err
}
