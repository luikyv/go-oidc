package models

import (
	"maps"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type DpopClaims struct {
	HttpMethod      string `json:"htm"`
	HttpUri         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
	// AccessToken should be filled when the DPoP ath claim is expected and should be validated.
	AccessToken   string
	JwkThumbprint string
}

type IdTokenOptions struct {
	Nonce                   string
	SignatureAlgorithm      jose.SignatureAlgorithm
	AdditionalIdTokenClaims map[string]string
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

type TokenOptions struct {
	TokenFormat           constants.TokenFormat
	ExpiresInSecs         int
	IsRefreshable         bool
	RefreshLifetimeSecs   int
	JwtSignatureKeyId     string
	OpaqueTokenLength     int
	AdditionalTokenClaims map[string]string
}

func (opts *TokenOptions) AddTokenClaims(claims map[string]string) {
	maps.Copy(opts.AdditionalTokenClaims, claims)
}

type GrantOptions struct {
	SessionId          string
	GrantType          constants.GrantType
	Subject            string
	ClientId           string
	Scopes             string
	DpopJwt            string
	CreatedAtTimestamp int
	TokenOptions
	IdTokenOptions
}

func (grantOptions GrantOptions) ShouldGenerateRefreshToken() bool {
	// There is no need to create a refresh token for the client credentials grant since no user consent is needed.
	return grantOptions.GrantType != constants.ClientCredentialsGrant && grantOptions.IsRefreshable
}

func (grantOptions GrantOptions) ShouldGenerateIdToken() bool {
	return unit.ScopesContainsOpenId(grantOptions.Scopes)
}

func (grantOptions GrantOptions) ShouldSaveSession() bool {
	if grantOptions.GrantType == constants.ClientCredentialsGrant && grantOptions.TokenFormat == constants.JwtTokenFormat {
		return false
	}

	return grantOptions.TokenFormat == constants.OpaqueTokenFormat || grantOptions.IsRefreshable || unit.ScopesContainsOpenId(grantOptions.Scopes)
}

type ClientAuthnRequest struct {
	ClientIdBasicAuthn     string
	ClientSecretBasicAuthn string
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ClientIdPost        string                        `form:"client_id"`
	ClientSecretPost    string                        `form:"client_secret"`
	ClientAssertionType constants.ClientAssertionType `form:"client_assertion_type"`
	ClientAssertion     string                        `form:"client_assertion"`
}

type TokenRequest struct {
	ClientAuthnRequest
	DpopJwt           string
	GrantType         constants.GrantType `form:"grant_type" binding:"required"`
	Scopes            string              `form:"scope"`
	AuthorizationCode string              `form:"code"`
	RedirectUri       string              `form:"redirect_uri"`
	RefreshToken      string              `form:"refresh_token"`
	CodeVerifier      string              `form:"code_verifier"`
}

type TokenResponse struct {
	AccessToken  string              `json:"access_token"`
	IdToken      string              `json:"id_token,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty"`
	ExpiresIn    int                 `json:"expires_in"`
	TokenType    constants.TokenType `json:"token_type"`
	Scope        string              `json:"scope,omitempty"`
}

type AuthorizationParameters struct {
	RequestUri          string                        `form:"request_uri" json:"request_uri"`
	RequestObject       string                        `form:"request" json:"request"`
	RedirectUri         string                        `form:"redirect_uri" json:"redirect_uri"`
	ResponseMode        constants.ResponseMode        `form:"response_mode" json:"response_mode"`
	ResponseType        constants.ResponseType        `form:"response_type" json:"response_type"`
	Scopes              string                        `form:"scope" json:"scope"`
	State               string                        `form:"state" json:"state"`
	Nonce               string                        `form:"nonce" json:"nonce"`
	CodeChallenge       string                        `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod constants.CodeChallengeMethod `form:"code_challenge_method" json:"code_challenge_method"`
}

func (params AuthorizationParameters) NewRedirectError(
	errorCode constants.ErrorCode,
	errorDescription string,
) OAuthRedirectError {
	return NewOAuthRedirectError(errorCode, errorDescription, params)
}

func (priorities AuthorizationParameters) Merge(params AuthorizationParameters) AuthorizationParameters {
	return AuthorizationParameters{
		RedirectUri:         unit.GetNonEmptyOrDefault(priorities.RedirectUri, params.RedirectUri),
		ResponseMode:        unit.GetNonEmptyOrDefault(priorities.ResponseMode, params.ResponseMode),
		ResponseType:        unit.GetNonEmptyOrDefault(priorities.ResponseType, params.ResponseType),
		Scopes:              unit.GetNonEmptyOrDefault(priorities.Scopes, params.Scopes),
		State:               unit.GetNonEmptyOrDefault(priorities.State, params.State),
		Nonce:               unit.GetNonEmptyOrDefault(priorities.Nonce, params.Nonce),
		CodeChallenge:       unit.GetNonEmptyOrDefault(priorities.CodeChallenge, params.CodeChallenge),
		CodeChallengeMethod: unit.GetNonEmptyOrDefault(priorities.CodeChallengeMethod, params.CodeChallengeMethod),
	}
}

type AuthorizationRequest struct {
	ClientId string `form:"client_id" json:"client_id"`
	AuthorizationParameters
}

type PushedAuthorizationRequest struct {
	ClientAuthnRequest
	AuthorizationParameters
}

type PushedAuthorizationResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type DynamicClientRequest struct {
	Id                      string
	Secret                  string
	RegistrationAccessToken string
	ClientMetaInfo
}

type DynamicClientResponse struct {
	Id                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationUri         string `json:"registration_client_uri"`
	ClientMetaInfo
}

type OpenIdConfiguration struct {
	Issuer                               string                            `json:"issuer"`
	ClientRegistrationEndpoint           string                            `json:"registration_endpoint"`
	AuthorizationEndpoint                string                            `json:"authorization_endpoint"`
	TokenEndpoint                        string                            `json:"token_endpoint"`
	UserinfoEndpoint                     string                            `json:"userinfo_endpoint"`
	JwksUri                              string                            `json:"jwks_uri"`
	ParEndpoint                          string                            `json:"pushed_authorization_request_endpoint,omitempty"`
	ParIsRequired                        bool                              `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                        []constants.ResponseType          `json:"response_types_supported"`
	ResponseModes                        []constants.ResponseMode          `json:"response_modes_supported"`
	GrantTypes                           []constants.GrantType             `json:"grant_types_supported"`
	Scopes                               []string                          `json:"scopes_supported"`
	SubjectIdentifierTypes               []constants.SubjectIdentifierType `json:"subject_types_supported"`
	IdTokenSigningAlgorithms             []jose.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported"`
	ClientAuthnMethods                   []constants.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
	JarIsRequired                        bool                              `json:"require_signed_request_object,omitempty"`
	JarIsEnabled                         bool                              `json:"request_parameter_supported"`
	JarAlgorithms                        []jose.SignatureAlgorithm         `json:"request_object_signing_alg_values_supported,omitempty"`
	JarmAlgorithms                       []jose.SignatureAlgorithm         `json:"authorization_signing_alg_values_supported,omitempty"`
	TokenEndpointClientSigningAlgorithms []jose.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg_values_supported"`
	IssuerResponseParameterIsEnabled     bool                              `json:"authorization_response_iss_parameter_supported"`
	DpopSigningAlgorithms                []jose.SignatureAlgorithm         `json:"dpop_signing_alg_values_supported,omitempty"`
}

type RedirectResponse struct {
	RedirectUri  string
	ResponseMode constants.ResponseMode
	Code         string
	AccessToken  string
	TokenType    constants.TokenType
	IdToken      string
	State        string
	// TODO
}

type ClientAuthnOptions struct {
	Methods                   []constants.ClientAuthnType
	ClientSignatureAlgorithms []jose.SignatureAlgorithm
}

type Token struct {
	Id            string
	Format        constants.TokenFormat
	Value         string
	Type          constants.TokenType
	JwkThumbprint string
}
