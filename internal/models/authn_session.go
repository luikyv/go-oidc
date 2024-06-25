package models

import (
	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type AuthnSession struct {
	Id                          string                      `json:"id" bson:"_id"`
	CallbackId                  string                      `json:"callback_id" bson:"callback_id"`
	PolicyId                    string                      `json:"policy_id" bson:"policy_id"`
	ExpiresAtTimestamp          int                         `json:"expires_at" bson:"expires_at"`
	CreatedAtTimestamp          int                         `json:"created_at" bson:"created_at"`
	Subject                     string                      `json:"sub" bson:"sub"`
	ClientId                    string                      `json:"client_id" bson:"client_id"`
	GrantedScopes               string                      `json:"granted_scopes" bson:"granted_scopes"`
	GrantedAuthorizationDetails []goidc.AuthorizationDetail `json:"granted_authorization_details,omitempty" bson:"granted_authorization_details,omitempty"`
	AuthorizationCode           string                      `json:"authorization_code,omitempty" bson:"authorization_code,omitempty"`
	AuthorizationCodeIssuedAt   int                         `json:"authorization_code_issued_at,omitempty" bson:"authorization_code_issued_at,omitempty"`
	// Custom parameters sent by PAR or JAR.
	ProtectedParameters map[string]any `json:"protected_params,omitempty" bson:"protected_params,omitempty"`
	// Allow the developer to store information in memory and, hence, between steps.
	Store                    map[string]any `json:"store,omitempty" bson:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty" bson:"additional_token_claims,omitempty"`
	AdditionalIdTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty" bson:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty" bson:"additional_user_info_claims,omitempty"`
	AuthorizationParameters  `bson:"inline"`
	Error                    OAuthError `json:"-" bson:"-"`
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

func (session AuthnSession) GetCallbackId() string {
	return session.CallbackId
}

func (session AuthnSession) GetClaims() (goidc.ClaimsObject, bool) {
	if session.Claims == nil {
		return goidc.ClaimsObject{}, false
	}
	return *session.Claims, true
}

func (session AuthnSession) GetAuthorizationDetails() ([]goidc.AuthorizationDetail, bool) {
	if session.AuthorizationDetails == nil {
		return nil, false
	}
	return session.AuthorizationDetails, true
}

func (session AuthnSession) GetScopes() string {
	return session.Scopes
}

func (session AuthnSession) GetPromptType() (goidc.PromptType, bool) {
	if session.Prompt == "" {
		return "", false
	}

	return session.Prompt, true
}

func (session AuthnSession) GetMaxAuthenticationAgeSecs() (int, bool) {
	if session.MaxAuthenticationAgeSecs == nil {
		return 0, false
	}

	return *session.MaxAuthenticationAgeSecs, true
}

func (session AuthnSession) GetDisplayValue() (goidc.DisplayValue, bool) {
	if session.Display == "" {
		return "", false
	}

	return session.Display, true
}

func (session AuthnSession) GetAcrValues() ([]goidc.AuthenticationContextReference, bool) {
	if session.AcrValues == "" {
		return nil, false
	}
	acrValues := []goidc.AuthenticationContextReference{}
	for _, acrValue := range unit.SplitStringWithSpaces(session.AcrValues) {
		acrValues = append(acrValues, goidc.AuthenticationContextReference(acrValue))
	}
	return acrValues, true
}

// Update the session with the parameters from an authorization request
// The parameters already present in the session have priority.
func (session *AuthnSession) UpdateParams(params AuthorizationParameters) {
	session.AuthorizationParameters = session.AuthorizationParameters.Merge(params)
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

func (session *AuthnSession) SaveParameter(key string, value any) {
	session.Store[key] = value
}

func (session AuthnSession) GetParameter(key string) (any, bool) {
	value, ok := session.Store[key]
	return value, ok
}

func (session *AuthnSession) AddTokenClaim(claim string, value any) {
	session.AdditionalTokenClaims[claim] = value
}

func (session *AuthnSession) AddIdTokenClaim(claim string, value any) {
	session.AdditionalIdTokenClaims[claim] = value
}

func (session *AuthnSession) AddUserInfoClaim(claim string, value any) {
	session.AdditionalUserInfoClaims[claim] = value
}

func (session AuthnSession) IsPushedRequestExpired(parLifetimeSecs int) bool {
	return unit.GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session AuthnSession) IsAuthorizationCodeExpired() bool {
	return unit.GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session AuthnSession) IsExpired() bool {
	return unit.GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session *AuthnSession) Push(parLifetimeSecs int) (requestUri string) {
	session.RequestUri = unit.GenerateRequestUri()
	session.ExpiresAtTimestamp = unit.GetTimestampNow() + parLifetimeSecs
	return session.RequestUri
}

func (session *AuthnSession) Start(policyId string, sessionLifetimeSecs int) {
	if session.Nonce != "" {
		session.AdditionalIdTokenClaims[string(goidc.NonceClaim)] = session.Nonce
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
	session.ExpiresAtTimestamp = session.AuthorizationCodeIssuedAt + goidc.AuthorizationCodeLifetimeSecs
	return session.AuthorizationCode
}

func (session *AuthnSession) GrantScopes(scopes string) {
	session.GrantedScopes = scopes
}

// Set the authorization details the client will have permissions to use.
// This will only have effect if support for authorization details was enabled.
func (session *AuthnSession) GrantAuthorizationDetails(authDetails []goidc.AuthorizationDetail) {
	session.GrantedAuthorizationDetails = authDetails
}

func (session AuthnSession) GetAdditionalIdTokenClaims() map[string]any {
	return session.AdditionalIdTokenClaims
}

func (session AuthnSession) GetAdditionalUserInfoClaims() map[string]any {
	return session.AdditionalUserInfoClaims
}

// Get custom protected parameters sent during PAR or JAR.
func (session AuthnSession) GetProtectedParameter(key string) (any, bool) {
	value, ok := session.ProtectedParameters[key]
	return value, ok
}

func (session *AuthnSession) SetRedirectError(errorCode goidc.ErrorCode, errorDescription string) {
	session.Error = session.NewRedirectError(errorCode, errorDescription)
}
