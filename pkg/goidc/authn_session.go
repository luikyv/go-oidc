package goidc

import (
	"context"
	"time"
)

type AuthnSessionManager interface {
	Save(ctx context.Context, session *AuthnSession) error
	GetByCallbackID(ctx context.Context, callbackID string) (*AuthnSession, error)
	GetByAuthorizationCode(ctx context.Context, authorizationCode string) (*AuthnSession, error)
	GetByRequestURI(ctx context.Context, requestURI string) (*AuthnSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthnSession struct {
	ID                          string                `json:"id"`
	CallbackID                  string                `json:"callback_id"`
	PolicyID                    string                `json:"policy_id"`
	ExpiresAtTimestamp          int64                 `json:"expires_at"`
	CreatedAtTimestamp          int64                 `json:"created_at"`
	Subject                     string                `json:"sub"`
	ClientID                    string                `json:"client_id"`
	GrantedScopes               string                `json:"granted_scopes"`
	GrantedAuthorizationDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty"`
	AuthorizationCode           string                `json:"authorization_code,omitempty"`
	// ProtectedParameters contains custom parameters sent by PAR.
	ProtectedParameters map[string]any `json:"protected_params,omitempty"`
	// Store allows developers to store information between user interactions.
	Store                    map[string]any `json:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty"`
	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty"`
	AuthorizationParameters
	Error error `json:"-"`
}

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

func (s *AuthnSession) SetClaimToken(claim string, value any) {
	if s.AdditionalTokenClaims == nil {
		s.AdditionalTokenClaims = make(map[string]any)
	}
	s.AdditionalTokenClaims[claim] = value
}

func (s *AuthnSession) SetACRClaimIDToken(acr ACR) {
	s.SetClaimIDToken(ClaimAuthenticationContextReference, acr)
}

func (s *AuthnSession) SetAuthTimeClaimIDToken(authTime int) {
	s.SetClaimIDToken(ClaimAuthenticationTime, authTime)
}

func (s *AuthnSession) SetAMRClaimIDToken(amrs ...AMR) {
	s.SetClaimIDToken(ClaimAuthenticationMethodReferences, amrs)
}

func (s *AuthnSession) SetClaimIDToken(claim string, value any) {
	if s.AdditionalIDTokenClaims == nil {
		s.AdditionalIDTokenClaims = make(map[string]any)
	}
	s.AdditionalIDTokenClaims[claim] = value
}

func (s *AuthnSession) SetACRClaimUserInfo(acr ACR) {
	s.SetClaimUserInfo(ClaimAuthenticationContextReference, acr)
}

func (s *AuthnSession) SetAuthTimeClaimUserInfo(authTime int) {
	s.SetClaimUserInfo(ClaimAuthenticationTime, authTime)
}

func (s *AuthnSession) SetAMRClaimUserInfo(amrs ...AMR) {
	s.SetClaimUserInfo(ClaimAuthenticationMethodReferences, amrs)
}

func (s *AuthnSession) SetClaimUserInfo(claim string, value any) {
	if s.AdditionalUserInfoClaims == nil {
		s.AdditionalUserInfoClaims = make(map[string]any)
	}
	s.AdditionalUserInfoClaims[claim] = value
}

func (s *AuthnSession) GrantScopes(scopes string) {
	s.GrantedScopes = scopes
}

// GrantAuthorizationDetails sets the authorization details the client will have permissions to use.
// This will only have effect if support for authorization details was enabled.
func (s *AuthnSession) GrantAuthorizationDetails(authDetails []AuthorizationDetail) {
	s.GrantedAuthorizationDetails = authDetails
}

func (s *AuthnSession) IsExpired() bool {
	return time.Now().Unix() > s.ExpiresAtTimestamp
}
