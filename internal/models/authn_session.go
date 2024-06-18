package models

import (
	"strconv"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/unit"
)

type AuthnSession struct {
	Id                        string         `json:"id"`
	CallbackId                string         `json:"callback_id"`
	PolicyId                  string         `json:"policy_d"`
	ExpiresAtTimestamp        int            `json:"expires_at"`
	CreatedAtTimestamp        int            `json:"created_at"`
	Subject                   string         `json:"sub"`
	ClientId                  string         `json:"client_id"`
	GrantedScopes             string         `json:"granted_scopes"`
	AuthorizationCode         string         `json:"authorization_code"`
	AuthorizationCodeIssuedAt int            `json:"authorization_code_issued_at"`
	ProtectedParameters       map[string]any `json:"protected_params"` // Custom parameters sent by PAR or JAR.
	Store                     map[string]any `json:"store"`            // Allow the developer to store information in memory and, hence, between steps.
	AdditionalTokenClaims     map[string]any `json:"additional_token_claims"`
	AdditionalIdTokenClaims   map[string]any `json:"additional_id_token_claims"`
	AdditionalUserInfoClaims  map[string]any `json:"additional_user_info_claims"`
	AuthorizationParameters
}

func NewSession(authParams AuthorizationParameters, client Client) AuthnSession {
	return AuthnSession{
		Id:                       uuid.NewString(),
		ClientId:                 client.Id,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       unit.GetTimestampNow(),
		Store:                    make(map[string]any),
		AdditionalTokenClaims:    make(map[string]any),
		AdditionalIdTokenClaims:  map[string]any{},
		AdditionalUserInfoClaims: map[string]any{},
	}
}

// Update the session with the parameters from an authorization request
// The parameters already present in the session have priority.
func (session *AuthnSession) UpdateParams(params AuthorizationParameters) {
	session.AuthorizationParameters = session.AuthorizationParameters.Merge(params)
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

// Sava a paramater in the session so it can be used across steps.
func (session *AuthnSession) SaveParameter(key string, value string) {
	session.Store[key] = value
}

func (session *AuthnSession) GetParameter(key string) any {
	return session.Store[key]
}

// Set a new claim that will be mapped in the access token when issued.
func (session *AuthnSession) AddTokenClaim(claim string, value any) {
	session.AdditionalTokenClaims[claim] = value
}

// Set a new claim that will be mapped in the ID token when issued.
func (session *AuthnSession) AddIdTokenClaim(claim string, value any) {
	session.AdditionalIdTokenClaims[claim] = value
}

// Set a new claim that will be mapped in the user info endpoint.
func (session *AuthnSession) AddUserInfoClaim(claim string, value any) {
	session.AdditionalUserInfoClaims[claim] = value
}

func (session *AuthnSession) IsPushedRequestExpired(parLifetimeSecs int) bool {
	return unit.GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session *AuthnSession) IsAuthorizationCodeExpired() bool {
	return unit.GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session *AuthnSession) Push(parLifetimeSecs int) (requestUri string) {
	session.RequestUri = unit.GenerateRequestUri()
	session.ExpiresAtTimestamp = unit.GetTimestampNow() + parLifetimeSecs
	return session.RequestUri
}

func (session *AuthnSession) Start(policyId string, sessionLifetimeSecs int) {
	if session.Nonce != "" {
		session.AdditionalIdTokenClaims[string(constants.NonceClaim)] = session.Nonce
	}
	session.PolicyId = policyId
	session.CallbackId = unit.GenerateCallbackId()
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestUri = ""
	session.ExpiresAtTimestamp = unit.GetTimestampNow() + sessionLifetimeSecs
}

func (session *AuthnSession) InitAuthorizationCode() string {
	session.AuthorizationCode = unit.GenerateAuthorizationCode()
	session.AuthorizationCodeIssuedAt = unit.GetTimestampNow()
	session.ExpiresAtTimestamp = session.AuthorizationCodeIssuedAt + constants.AuthorizationCodeLifetimeSecs
	return session.AuthorizationCode
}

func (session *AuthnSession) GrantScopes(scopes string) {
	session.GrantedScopes = scopes
}

func (session AuthnSession) GetAdditionalIdTokenClaims() map[string]any {
	return session.AdditionalIdTokenClaims
}

func (session AuthnSession) GetAdditionalUserInfoClaims() map[string]any {
	return session.AdditionalUserInfoClaims
}

func (session *AuthnSession) MustAuthenticateUser(authTime int) bool {
	if session.Prompt == constants.LoginPromptType {
		return true
	}

	if session.MaxAuthenticationAgeSecs == "" {
		return false
	}

	maxAge, err := strconv.Atoi(session.MaxAuthenticationAgeSecs)
	if err != nil {
		return false
	}
	return unit.GetTimestampNow() > authTime+maxAge
}

// Get custome protected parameters sent during PAR or JAR.
func (session *AuthnSession) GetProtectedParameter(key string) any {
	return session.ProtectedParameters[key]
}
