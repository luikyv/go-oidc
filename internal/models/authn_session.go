package models

import (
	"strconv"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnSession struct {
	Id                 string `json:"id"`
	CallbackId         string `json:"callback_id"`
	PolicyId           string `json:"policy_d"`
	AuthnSequenceIndex int    `json:"policy_step_index"`
	ExpiresAtTimestamp int    `json:"expires_at"`
	CreatedAtTimestamp int    `json:"created_at"`
	Subject            string `json:"sub"`
	ClientId           string `json:"client_id"`
	AuthorizationParameters
	GrantedScopes                      string                                    `json:"granted_scopes"`
	AuthorizationCode                  string                                    `json:"authorization_code"`
	AuthorizationCodeIssuedAt          int                                       `json:"authorization_code_issued_at"`
	UserAuthenticatedAtTimestamp       int                                       `json:"auth_time"`
	UserAuthenticationMethodReferences []constants.AuthenticationMethodReference `json:"amr"`
	ProtectedParameters                map[string]any                            `json:"protected_params"` // Custom parameters sent by PAR or JAR.
	Store                              map[string]any                            `json:"store"`            // Allow the developer to store information in memory and, hence, between steps.
	AdditionalTokenClaims              map[string]any                            `json:"token_claims"`     // Allow the developer to map new (or override the default) claims to the access token.
	AdditionalIdTokenClaims            map[string]any                            `json:"id_token_claims"`  // Allow the developer to map new (or override the default) claims to the ID token.
}

func NewSession(authParams AuthorizationParameters, client Client) AuthnSession {
	return AuthnSession{
		Id:                      uuid.NewString(),
		ClientId:                client.Id,
		AuthorizationParameters: authParams,
		CreatedAtTimestamp:      unit.GetTimestampNow(),
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
func (session *AuthnSession) SetCustomTokenClaim(key string, value string) {
	session.AdditionalTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomTokenClaim(key string, value string) any {
	return session.AdditionalTokenClaims[key]
}

// Set a new claim that will be mapped in the ID token when issued.
func (session *AuthnSession) SetCustomIdTokenClaim(key string, value string) {
	session.AdditionalIdTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomIdTokenClaim(key string, value string) any {
	return session.AdditionalIdTokenClaims[key]
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
	session.PolicyId = policyId
	session.AuthnSequenceIndex = 0
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

func (session *AuthnSession) GetIdTokenOptions() IdTokenOptions {
	return IdTokenOptions{
		Nonce:                              session.Nonce,
		UserAuthenticatedAtTimestamp:       session.UserAuthenticatedAtTimestamp,
		UserAuthenticationMethodReferences: session.UserAuthenticationMethodReferences,
		AdditionalIdTokenClaims:            session.AdditionalIdTokenClaims,
	}
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

// This method must be called after the user is authenticated.
// This will set the authentication methods used and the time the authentication occurred.
func (session *AuthnSession) SetUserAuthentication(authMethods ...constants.AuthenticationMethodReference) {
	session.UserAuthenticatedAtTimestamp = unit.GetTimestampNow()
	session.UserAuthenticationMethodReferences = authMethods
}

// Get custome protected parameters sent during PAR or JAR.
func (session *AuthnSession) GetProtectedParameter(key string) any {
	return session.ProtectedParameters[key]
}
