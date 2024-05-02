package models

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type AuthnSession struct {
	Id                      string
	Profile                 constants.Profile
	CallbackId              string
	GrantModelId            string
	StepIdsLeft             []string
	CreatedAtTimestamp      int
	Subject                 string
	ClientId                string
	RequestUri              string
	RequestObject           string
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

func NewSessionFromRequest(req BaseAuthorizationRequest, client Client) AuthnSession {

	return AuthnSession{
		Id:                      uuid.NewString(),
		ClientId:                client.Id,
		GrantModelId:            client.DefaultGrantModelId,
		RequestObject:           req.Request,
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

func (session *AuthnSession) Push(reqCtx *gin.Context) {
	session.RequestUri = unit.GenerateRequestUri()
	session.PushedParameters = extractPushedParams(reqCtx)
}

func (session *AuthnSession) Init() {
	if session.CodeChallengeMethod == "" {
		session.CodeChallengeMethod = constants.PlainCodeChallengeMethod
	}
	session.CallbackId = unit.GenerateCallbackId()
	// If either an empty or the "jwt" response modes are passed, we must find the default value based on the response type.
	if session.ResponseMode == "" {
		session.ResponseMode = getDefaultResponseMode(session.ResponseType)
	}
	if session.ResponseMode == constants.JwtResponseMode {
		session.ResponseMode = getDefaultJarmResponseMode(session.ResponseType)
	}
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestUri = ""
}

// Update the session with the parameters from an authorization request
// The parameters already present in the session take prioritybut not sent during par.
func (session *AuthnSession) UpdateWithRequest(req AuthorizationRequest) {

	if session.RedirectUri == "" {
		session.RedirectUri = req.RedirectUri
	}

	if len(session.Scopes) == 0 {
		session.Scopes = unit.SplitStringWithSpaces(req.Scope)
	}

	if session.ResponseType == "" {
		session.ResponseType = req.ResponseType
	}

	if session.ResponseMode == "" {
		session.ResponseMode = req.ResponseMode
	}

	if session.State == "" {
		session.State = req.State
	}

	if session.CodeChallenge == "" {
		session.CodeChallenge = req.CodeChallenge
	}

	if session.CodeChallengeMethod == "" {
		session.CodeChallengeMethod = req.CodeChallengeMethod
	}

	if session.Nonce == "" {
		session.Nonce = req.Nonce
	}
}

func extractPushedParams(reqCtx *gin.Context) map[string]string {
	// Load the parameters sent using PAR.
	if err := reqCtx.Request.ParseForm(); err != nil {
		return map[string]string{}
	}

	pushedParams := make(map[string]string)
	for param, values := range reqCtx.Request.PostForm {
		pushedParams[param] = values[0]
	}

	return pushedParams
}

func getDefaultResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
	if responseType.IsImplict() {
		return constants.FragmentResponseMode
	}

	return constants.QueryResponseMode
}

func getDefaultJarmResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
	if responseType.IsImplict() {
		return constants.FragmentJwtResponseMode
	}

	return constants.QueryJwtResponseMode
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
