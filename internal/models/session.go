package models

import (
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnSession struct {
	Id                    string
	CallbackId            string
	StepId                string
	CreatedAtTimestamp    int
	Subject               string
	ClientId              string
	RequestUri            string
	Scopes                []string
	RedirectUri           string
	State                 string
	CodeChallenge         string
	CodeChallengeMethod   constants.CodeChallengeMethod
	AuthorizationCode     string
	AuthorizedAtTimestamp int
	Store                 map[string]string // Allow the developer to store information in memory and, hence, between steps.
	AdditionalClaims      map[string]string // Allow the developer to map new (or override the default) claims in the access token.
	ClientAttributes      map[string]string // Allow the developer to access the client's custom attributes.
	// In case the authentication flow fails, these values can be used to override the default error information.
	ErrorCode        constants.ErrorCode
	ErrorDescription string
}

func NewSessionForAuthorizeRequest(req AuthorizeRequest, client Client) AuthnSession {
	return AuthnSession{
		Id:                  uuid.NewString(),
		CallbackId:          unit.GenerateCallbackId(),
		ClientId:            req.ClientId,
		Scopes:              unit.SplitStringWithSpaces(req.Scope),
		RedirectUri:         req.RedirectUri,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAtTimestamp:  unit.GetTimestampNow(),
		Store:               make(map[string]string),
		AdditionalClaims:    make(map[string]string),
	}
}

func NewSessionForPARRequest(req PARRequest, client Client) AuthnSession {
	return AuthnSession{
		Id:                  uuid.NewString(),
		RequestUri:          unit.GenerateRequestUri(),
		ClientId:            client.Id,
		Scopes:              strings.Split(req.Scope, " "),
		RedirectUri:         req.RedirectUri,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAtTimestamp:  unit.GetTimestampNow(),
		Store:               make(map[string]string),
		AdditionalClaims:    make(map[string]string),
		ClientAttributes:    client.Attributes,
	}
}

func (session *AuthnSession) SetUserId(userId string) {
	session.Subject = userId
}

func (session *AuthnSession) SetError(errorCode constants.ErrorCode, errorDescription string) {
	session.ErrorCode = errorCode
	session.ErrorDescription = errorDescription
}

func (session *AuthnSession) SaveParameter(key string, value string) {
	session.Store[key] = value
}

func (session *AuthnSession) GetParameter(key string, value string) string {
	return session.Store[key]
}

func (session *AuthnSession) SetCustomClaim(key string, value string) {
	session.AdditionalClaims[key] = value
}

func (session *AuthnSession) GetCustomClaim(key string, value string) string {
	return session.AdditionalClaims[key]
}
