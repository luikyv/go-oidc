package models

import (
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnSession struct {
	Id                      string
	CallbackId              string
	GrantModelId            string
	StepIdsLeft             []string
	CreatedAtTimestamp      int
	Subject                 string
	ClientId                string
	RequestUri              string
	Scopes                  []string
	RedirectUri             string
	ResponseType            constants.ResponseType
	ResponseMode            constants.ResponseMode
	State                   string
	Nonce                   string
	CodeChallenge           string
	CodeChallengeMethod     constants.CodeChallengeMethod
	AuthorizationCode       string
	AuthorizedAtTimestamp   int
	PushedParameters        map[string]string // Parameters sent using the PAR endpoint.
	Store                   map[string]string // Allow the developer to store information in memory and, hence, between steps.
	AdditionalTokenClaims   map[string]string // Allow the developer to map new (or override the default) claims to the access token.
	AdditionalIdTokenClaims map[string]string // Allow the developer to map new (or override the default) claims to the ID token.
	ClientAttributes        map[string]string // Allow the developer to access the client's custom attributes.
}

func newSessionForBaseAuthorizeRequest(req BaseAuthorizeRequest, client Client) AuthnSession {
	return AuthnSession{
		Id:                      uuid.NewString(),
		ClientId:                client.Id,
		GrantModelId:            client.DefaultGrantModelId,
		Scopes:                  unit.SplitStringWithSpaces(req.Scope),
		RedirectUri:             req.RedirectUri,
		ResponseType:            req.ResponseType,
		ResponseMode:            req.ResponseMode,
		State:                   req.State,
		Nonce:                   req.Nonce,
		CodeChallenge:           req.CodeChallenge,
		CodeChallengeMethod:     req.CodeChallengeMethod,
		CreatedAtTimestamp:      unit.GetTimestampNow(),
		PushedParameters:        make(map[string]string),
		Store:                   make(map[string]string),
		AdditionalTokenClaims:   make(map[string]string),
		AdditionalIdTokenClaims: make(map[string]string),
		ClientAttributes:        client.Attributes,
	}
}

func NewSessionForAuthorizeRequest(req AuthorizeRequest, client Client) AuthnSession {
	session := newSessionForBaseAuthorizeRequest(req.BaseAuthorizeRequest, client)
	session.CallbackId = unit.GenerateCallbackId()
	return session
}

func NewSessionForPARRequest(req PARRequest, client Client, pushedParams map[string]string) AuthnSession {
	session := newSessionForBaseAuthorizeRequest(req.BaseAuthorizeRequest, client)
	session.RequestUri = unit.GenerateRequestUri()
	session.PushedParameters = pushedParams
	return session
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

// Sava a paramater in the session so it can be used across steps.
func (session *AuthnSession) SaveParameter(key string, value string) {
	session.Store[key] = value
}

func (session *AuthnSession) GetParameter(key string) string {
	return session.Store[key]
}

func (session *AuthnSession) GetClientAttribute(key string) string {
	return session.ClientAttributes[key]
}

// Set a new claim that will be mapped in the access token when issued.
func (session *AuthnSession) SetCustomTokenClaim(key string, value string) {
	session.AdditionalTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomTokenClaim(key string, value string) string {
	return session.AdditionalTokenClaims[key]
}

// Set a new claim that will be mapped in the ID token when issued.
func (session *AuthnSession) SetCustomIdTokenClaim(key string, value string) {
	session.AdditionalIdTokenClaims[key] = value
}

func (session *AuthnSession) GetCustomIdTokenClaim(key string, value string) string {
	return session.AdditionalIdTokenClaims[key]
}

// Make sure the request URI can't be used again.
func (session *AuthnSession) EraseRequestUri() {
	session.RequestUri = ""
}

func (session *AuthnSession) InitCallbackId() {
	session.CallbackId = unit.GenerateCallbackId()
}

func (session *AuthnSession) SetAuthnSteps(stepIdSequence []string) {
	session.StepIdsLeft = stepIdSequence
}

func (session *AuthnSession) IsPushedRequestExpired() bool {
	return unit.GetTimestampNow() > session.CreatedAtTimestamp+constants.ParLifetimeSecs
}

func (session *AuthnSession) InitAuthorizationCode() {
	session.AuthorizationCode = unit.GenerateAuthorizationCode()
	session.AuthorizedAtTimestamp = unit.GetTimestampNow()
}
