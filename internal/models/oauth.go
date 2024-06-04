package models

import (
	"maps"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type DpopClaims struct {
	HttpMethod      string `json:"htm"`
	HttpUri         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

type DpopValidationOptions struct {
	HttpMethod string
	HttpUri    string
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JwkThumbprint string
}

type IdTokenOptions struct {
	Nonce                              string                                    `json:"nonce"`
	AdditionalIdTokenClaims            map[string]any                            `json:"additional_id_token_claims"`
	UserAuthenticatedAtTimestamp       int                                       `json:"auth_time"`
	UserAuthenticationMethodReferences []constants.AuthenticationMethodReference `json:"amr"`
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

type TokenOptions struct {
	TokenFormat           constants.TokenFormat `json:"token_format"`
	TokenExpiresInSecs    int                   `json:"token_expires_in_secs"`
	ShouldRefresh         bool
	JwtSignatureKeyId     string         `json:"token_signature_key_id"`
	OpaqueTokenLength     int            `json:"opaque_token_length"`
	AdditionalTokenClaims map[string]any `json:"additional_token_claims"`
}

func (opts *TokenOptions) AddTokenClaims(claims map[string]any) {
	maps.Copy(opts.AdditionalTokenClaims, claims)
}

type GrantOptions struct {
	GrantType          constants.GrantType `json:"grant_type"`
	Subject            string              `json:"sub"`
	ClientId           string              `json:"client_id"`
	GrantedScopes      string              `json:"scopes"`
	CreatedAtTimestamp int                 `json:"created_at"`
	TokenOptions
	IdTokenOptions
}

type ClientAuthnRequest struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ClientId            string
	ClientSecret        string
	ClientAssertionType constants.ClientAssertionType
	ClientAssertion     string
}

func NewClientAuthnRequest(req *http.Request) ClientAuthnRequest {
	return ClientAuthnRequest{
		ClientId:            req.PostFormValue("client_id"),
		ClientSecret:        req.PostFormValue("client_secret"),
		ClientAssertionType: constants.ClientAssertionType(req.PostFormValue("client_assertion_type")),
		ClientAssertion:     req.PostFormValue("client_assertion"),
	}
}

type TokenRequest struct {
	ClientAuthnRequest
	// DpopJwt           string
	GrantType         constants.GrantType
	Scopes            string
	AuthorizationCode string
	RedirectUri       string
	RefreshToken      string
	CodeVerifier      string
}

func NewTokenRequest(req *http.Request) TokenRequest {
	return TokenRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		GrantType:          constants.GrantType(req.PostFormValue("grant_type")),
		Scopes:             req.PostFormValue("scope"),
		AuthorizationCode:  req.PostFormValue("code"),
		RedirectUri:        req.PostFormValue("redirect_uri"),
		RefreshToken:       req.PostFormValue("refresh_token"),
		CodeVerifier:       req.PostFormValue("code_verifier"),
	}
}

type TokenResponse struct {
	AccessToken  string              `json:"access_token"`
	IdToken      string              `json:"id_token,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty"`
	ExpiresIn    int                 `json:"expires_in"`
	TokenType    constants.TokenType `json:"token_type"`
	Scopes       string              `json:"scope,omitempty"`
}

type AuthorizationParameters struct {
	RequestUri               string                        `json:"request_uri"`
	RequestObject            string                        `json:"request"`
	RedirectUri              string                        `json:"redirect_uri"`
	ResponseMode             constants.ResponseMode        `json:"response_mode"`
	ResponseType             constants.ResponseType        `json:"response_type"`
	Scopes                   string                        `json:"scope"`
	State                    string                        `json:"state"`
	Nonce                    string                        `json:"nonce"`
	CodeChallenge            string                        `json:"code_challenge"`
	CodeChallengeMethod      constants.CodeChallengeMethod `json:"code_challenge_method"`
	Prompt                   constants.PromptType          `json:"prompt"`
	MaxAuthenticationAgeSecs string                        `json:"max_age"`
}

func (params AuthorizationParameters) NewRedirectError(
	errorCode constants.ErrorCode,
	errorDescription string,
) OAuthRedirectError {
	return NewOAuthRedirectError(errorCode, errorDescription, params)
}

func (insideParams AuthorizationParameters) Merge(outsideParams AuthorizationParameters) AuthorizationParameters {
	return AuthorizationParameters{
		RedirectUri:              unit.GetNonEmptyOrDefault(insideParams.RedirectUri, outsideParams.RedirectUri),
		ResponseMode:             unit.GetNonEmptyOrDefault(insideParams.ResponseMode, outsideParams.ResponseMode),
		ResponseType:             unit.GetNonEmptyOrDefault(insideParams.ResponseType, outsideParams.ResponseType),
		Scopes:                   unit.GetNonEmptyOrDefault(insideParams.Scopes, outsideParams.Scopes),
		State:                    unit.GetNonEmptyOrDefault(insideParams.State, outsideParams.State),
		Nonce:                    unit.GetNonEmptyOrDefault(insideParams.Nonce, outsideParams.Nonce),
		CodeChallenge:            unit.GetNonEmptyOrDefault(insideParams.CodeChallenge, outsideParams.CodeChallenge),
		CodeChallengeMethod:      unit.GetNonEmptyOrDefault(insideParams.CodeChallengeMethod, outsideParams.CodeChallengeMethod),
		Prompt:                   unit.GetNonEmptyOrDefault(insideParams.Prompt, outsideParams.Prompt),
		MaxAuthenticationAgeSecs: unit.GetNonEmptyOrDefault(insideParams.MaxAuthenticationAgeSecs, outsideParams.MaxAuthenticationAgeSecs),
	}
}

type AuthorizationRequest struct {
	ClientId string `json:"client_id"`
	AuthorizationParameters
}

func NewAuthorizationRequest(req *http.Request) AuthorizationRequest {
	return AuthorizationRequest{
		ClientId: req.URL.Query().Get("client_id"),
		AuthorizationParameters: AuthorizationParameters{
			RequestUri:               req.URL.Query().Get("request_uri"),
			RequestObject:            req.URL.Query().Get("request"),
			RedirectUri:              req.URL.Query().Get("redirect_uri"),
			ResponseMode:             constants.ResponseMode(req.URL.Query().Get("response_mode")),
			ResponseType:             constants.ResponseType(req.URL.Query().Get("response_type")),
			Scopes:                   req.URL.Query().Get("scope"),
			State:                    req.URL.Query().Get("state"),
			Nonce:                    req.URL.Query().Get("nonce"),
			CodeChallenge:            req.URL.Query().Get("code_challenge"),
			CodeChallengeMethod:      constants.CodeChallengeMethod(req.URL.Query().Get("code_challenge_method")),
			Prompt:                   constants.PromptType(req.URL.Query().Get("prompt")),
			MaxAuthenticationAgeSecs: req.URL.Query().Get("max_age"),
		},
	}
}

type PushedAuthorizationRequest struct {
	ClientAuthnRequest
	AuthorizationParameters
}

func NewPushedAuthorizationRequest(req *http.Request) PushedAuthorizationRequest {
	return PushedAuthorizationRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		AuthorizationParameters: AuthorizationParameters{
			RequestUri:               req.PostFormValue("request_uri"),
			RequestObject:            req.PostFormValue("request"),
			RedirectUri:              req.PostFormValue("redirect_uri"),
			ResponseMode:             constants.ResponseMode(req.PostFormValue("response_mode")),
			ResponseType:             constants.ResponseType(req.PostFormValue("response_type")),
			Scopes:                   req.PostFormValue("scope"),
			State:                    req.PostFormValue("state"),
			Nonce:                    req.PostFormValue("nonce"),
			CodeChallenge:            req.PostFormValue("code_challenge"),
			CodeChallengeMethod:      constants.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
			Prompt:                   constants.PromptType(req.PostFormValue("prompt")),
			MaxAuthenticationAgeSecs: req.PostFormValue("max_age"),
		},
	}
}

type PushedAuthorizationResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type DynamicClientRequest struct {
	Id                      string
	InitialAccessToken      string
	RegistrationAccessToken string
	Secret                  string
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
	Issuer                                         string                            `json:"issuer"`
	ClientRegistrationEndpoint                     string                            `json:"registration_endpoint"`
	AuthorizationEndpoint                          string                            `json:"authorization_endpoint"`
	TokenEndpoint                                  string                            `json:"token_endpoint"`
	UserinfoEndpoint                               string                            `json:"userinfo_endpoint"`
	JwksEndpoint                                   string                            `json:"jwks_uri"`
	ParEndpoint                                    string                            `json:"pushed_authorization_request_endpoint,omitempty"`
	ParIsRequired                                  bool                              `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                                  []constants.ResponseType          `json:"response_types_supported"`
	ResponseModes                                  []constants.ResponseMode          `json:"response_modes_supported"`
	GrantTypes                                     []constants.GrantType             `json:"grant_types_supported"`
	Scopes                                         []string                          `json:"scopes_supported"`
	IdTokenClaimsSupported                         []constants.Claim                 `json:"claims_supported"`
	SubjectIdentifierTypes                         []constants.SubjectIdentifierType `json:"subject_types_supported"`
	IdTokenSignatureAlgorithms                     []jose.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported"`
	UserInfoSignatureAlgorithms                    []jose.SignatureAlgorithm         `json:"userinfo_signing_alg_values_supported"`
	ClientAuthnMethods                             []constants.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
	JarIsRequired                                  bool                              `json:"require_signed_request_object,omitempty"`
	JarIsEnabled                                   bool                              `json:"request_parameter_supported"`
	JarAlgorithms                                  []jose.SignatureAlgorithm         `json:"request_object_signing_alg_values_supported,omitempty"`
	JarmAlgorithms                                 []jose.SignatureAlgorithm         `json:"authorization_signing_alg_values_supported,omitempty"`
	TokenEndpointClientSigningAlgorithms           []jose.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg_values_supported"`
	IssuerResponseParameterIsEnabled               bool                              `json:"authorization_response_iss_parameter_supported"`
	DpopSignatureAlgorithms                        []jose.SignatureAlgorithm         `json:"dpop_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                          string                            `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointClientAuthnMethods        []constants.ClientAuthnType       `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointClientSignatureAlgorithms []jose.SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
}

type Token struct {
	Id            string
	Format        constants.TokenFormat
	Value         string
	Type          constants.TokenType
	JwkThumbprint string
}

type RedirectParameters struct {
	Response          string
	Issuer            string
	AccessToken       string
	TokenType         constants.TokenType
	IdToken           string
	AuthorizationCode string
	State             string
	Error             constants.ErrorCode
	ErrorDescription  string
}

func (rp RedirectParameters) GetParams() map[string]string {
	params := make(map[string]string)

	if rp.Response != "" {
		params["response"] = rp.Response
		return params
	}

	if rp.Issuer != "" {
		params["iss"] = rp.Issuer
	}
	if rp.AccessToken != "" {
		params["access_token"] = rp.AccessToken
	}
	if rp.TokenType != "" {
		params["token_type"] = string(rp.TokenType)
	}
	if rp.IdToken != "" {
		params["id_token"] = rp.IdToken
	}
	if rp.AuthorizationCode != "" {
		params["code"] = rp.AuthorizationCode
	}
	if rp.State != "" {
		params["state"] = rp.State
	}
	if rp.Error != "" {
		params["error"] = string(rp.Error)
	}
	if rp.ErrorDescription != "" {
		params["error_description"] = rp.ErrorDescription
	}

	return params
}

type UserInfoResponse struct {
	SignedClaims string
	Claims       map[string]any
}

type TokenIntrospectionRequest struct {
	ClientAuthnRequest
	Token         string
	TokenTypeHint constants.TokenTypeHint
}

func NewTokenIntrospectionRequest(req *http.Request) TokenIntrospectionRequest {
	return TokenIntrospectionRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		Token:              req.PostFormValue("token"),
		TokenTypeHint:      constants.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

type TokenIntrospectionInfo struct {
	IsActive           bool
	Scopes             string
	ClientId           string
	Subject            string
	ExpiresAtTimestamp int
	JwkThumbprint      string
	RawClaims          map[string]any
}

func (info TokenIntrospectionInfo) GetParameters() map[string]any {
	if !info.IsActive {
		return map[string]any{
			"active": false,
		}
	}

	params := map[string]any{
		"active":                        true,
		string(constants.SubjectClaim):  info.Subject,
		string(constants.ScopeClaim):    info.Scopes,
		string(constants.ClientIdClaim): info.ClientId,
		string(constants.ExpiryClaim):   info.ExpiresAtTimestamp,
	}

	if info.JwkThumbprint != "" {
		params["cnf"] = map[string]string{
			"jkt": info.JwkThumbprint,
		}
	}

	for k, v := range info.RawClaims {
		params[k] = v
	}

	return params
}
