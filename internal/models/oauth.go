package models

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type DpopJwtClaims struct {
	HttpMethod      string `json:"htm"`
	HttpUri         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

type DpopJwtValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JwkThumbprint string
}

type IdTokenOptions struct {
	Subject                 string
	ClientId                string
	AdditionalIdTokenClaims map[string]any
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

type GrantOptions struct {
	GrantType                   goidc.GrantType             `json:"grant_type"`
	Subject                     string                      `json:"sub"`
	ClientId                    string                      `json:"client_id"`
	GrantedScopes               string                      `json:"scopes"`
	GrantedAuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details"`
	CreatedAtTimestamp          int                         `json:"created_at"`
	AdditionalIdTokenClaims     map[string]any              `json:"additional_id_token_claims"`
	AdditionalUserInfoClaims    map[string]any              `json:"additional_user_info_claims"`
	goidc.TokenOptions
}

func (grantOpts GrantOptions) GetIdTokenOptions() IdTokenOptions {
	return IdTokenOptions{
		Subject:                 grantOpts.Subject,
		ClientId:                grantOpts.ClientId,
		AdditionalIdTokenClaims: grantOpts.AdditionalIdTokenClaims,
	}
}

type ClientAuthnRequest struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ClientId            string
	ClientSecret        string
	ClientAssertionType goidc.ClientAssertionType
	ClientAssertion     string
}

func NewClientAuthnRequest(req *http.Request) ClientAuthnRequest {
	return ClientAuthnRequest{
		ClientId:            req.PostFormValue("client_id"),
		ClientSecret:        req.PostFormValue("client_secret"),
		ClientAssertionType: goidc.ClientAssertionType(req.PostFormValue("client_assertion_type")),
		ClientAssertion:     req.PostFormValue("client_assertion"),
	}
}

type TokenRequest struct {
	ClientAuthnRequest
	GrantType         goidc.GrantType
	Scopes            string
	AuthorizationCode string
	RedirectUri       string
	RefreshToken      string
	CodeVerifier      string
}

func NewTokenRequest(req *http.Request) TokenRequest {
	return TokenRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		GrantType:          goidc.GrantType(req.PostFormValue("grant_type")),
		Scopes:             req.PostFormValue("scope"),
		AuthorizationCode:  req.PostFormValue("code"),
		RedirectUri:        req.PostFormValue("redirect_uri"),
		RefreshToken:       req.PostFormValue("refresh_token"),
		CodeVerifier:       req.PostFormValue("code_verifier"),
	}
}

type TokenResponse struct {
	AccessToken          string                      `json:"access_token"`
	IdToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int                         `json:"expires_in"`
	TokenType            goidc.TokenType             `json:"token_type"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
}

type AuthorizationParameters struct {
	RequestUri               string                      `json:"request_uri,omitempty"`
	RequestObject            string                      `json:"request,omitempty"`
	RedirectUri              string                      `json:"redirect_uri,omitempty"`
	ResponseMode             goidc.ResponseMode          `json:"response_mode,omitempty"`
	ResponseType             goidc.ResponseType          `json:"response_type,omitempty"`
	Scopes                   string                      `json:"scope,omitempty"`
	State                    string                      `json:"state,omitempty"`
	Nonce                    string                      `json:"nonce,omitempty"`
	CodeChallenge            string                      `json:"code_challenge,omitempty"`
	CodeChallengeMethod      goidc.CodeChallengeMethod   `json:"code_challenge_method,omitempty"`
	Prompt                   goidc.PromptType            `json:"prompt,omitempty"`
	MaxAuthenticationAgeSecs *int                        `json:"max_age,omitempty"`
	Display                  goidc.DisplayValue          `json:"display,omitempty"`
	AcrValues                string                      `json:"acr_values,omitempty"`
	Claims                   *goidc.ClaimsObject         `json:"claims,omitempty"` // Claims is a pointer to help differentiate when it's null or not.
	AuthorizationDetails     []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
}

func (params AuthorizationParameters) NewRedirectError(
	errorCode goidc.ErrorCode,
	errorDescription string,
) OAuthRedirectError {
	return NewOAuthRedirectError(errorCode, errorDescription, params)
}

func (insideParams AuthorizationParameters) Merge(outsideParams AuthorizationParameters) AuthorizationParameters {
	params := AuthorizationParameters{
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
		Display:                  unit.GetNonEmptyOrDefault(insideParams.Display, outsideParams.Display),
		AcrValues:                unit.GetNonEmptyOrDefault(insideParams.AcrValues, outsideParams.AcrValues),
		Claims:                   unit.GetNonNilOrDefault(insideParams.Claims, outsideParams.Claims),
		AuthorizationDetails:     unit.GetNonNilOrDefault(insideParams.AuthorizationDetails, outsideParams.AuthorizationDetails),
	}

	return params
}

// Get the response mode based on the response type.
func (params AuthorizationParameters) GetResponseMode() goidc.ResponseMode {
	if params.ResponseMode == "" {
		return params.ResponseType.GetDefaultResponseMode(false)
	}

	if params.ResponseMode == goidc.JwtResponseMode {
		return params.ResponseType.GetDefaultResponseMode(true)
	}

	return params.ResponseMode
}

type AuthorizationRequest struct {
	ClientId string `json:"client_id"`
	AuthorizationParameters
}

func NewAuthorizationRequest(req *http.Request) AuthorizationRequest {
	params := AuthorizationRequest{
		ClientId: req.URL.Query().Get("client_id"),
		AuthorizationParameters: AuthorizationParameters{
			RequestUri:          req.URL.Query().Get("request_uri"),
			RequestObject:       req.URL.Query().Get("request"),
			RedirectUri:         req.URL.Query().Get("redirect_uri"),
			ResponseMode:        goidc.ResponseMode(req.URL.Query().Get("response_mode")),
			ResponseType:        goidc.ResponseType(req.URL.Query().Get("response_type")),
			Scopes:              req.URL.Query().Get("scope"),
			State:               req.URL.Query().Get("state"),
			Nonce:               req.URL.Query().Get("nonce"),
			CodeChallenge:       req.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: goidc.CodeChallengeMethod(req.URL.Query().Get("code_challenge_method")),
			Prompt:              goidc.PromptType(req.URL.Query().Get("prompt")),
			Display:             goidc.DisplayValue(req.URL.Query().Get("display")),
			AcrValues:           req.URL.Query().Get("acr_values"),
		},
	}

	maxAge, err := strconv.Atoi(req.URL.Query().Get("max_age"))
	if err == nil {
		params.MaxAuthenticationAgeSecs = &maxAge
	}

	claims := req.URL.Query().Get("claims")
	if claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	authorizationDetails := req.URL.Query().Get("authorization_details")
	if authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return params
}

type PushedAuthorizationRequest struct {
	ClientAuthnRequest
	AuthorizationParameters
}

func NewPushedAuthorizationRequest(req *http.Request) PushedAuthorizationRequest {
	params := AuthorizationParameters{
		RequestUri:          req.PostFormValue("request_uri"),
		RequestObject:       req.PostFormValue("request"),
		RedirectUri:         req.PostFormValue("redirect_uri"),
		ResponseMode:        goidc.ResponseMode(req.PostFormValue("response_mode")),
		ResponseType:        goidc.ResponseType(req.PostFormValue("response_type")),
		Scopes:              req.PostFormValue("scope"),
		State:               req.PostFormValue("state"),
		Nonce:               req.PostFormValue("nonce"),
		CodeChallenge:       req.PostFormValue("code_challenge"),
		CodeChallengeMethod: goidc.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
		Prompt:              goidc.PromptType(req.PostFormValue("prompt")),
		Display:             goidc.DisplayValue(req.PostFormValue("display")),
		AcrValues:           req.PostFormValue("acr_values"),
	}

	maxAge, err := strconv.Atoi(req.PostFormValue("max_age"))
	if err == nil {
		params.MaxAuthenticationAgeSecs = &maxAge
	}

	claims := req.PostFormValue("claims")
	if claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	authorizationDetails := req.PostFormValue("authorization_details")
	if authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return PushedAuthorizationRequest{
		ClientAuthnRequest:      NewClientAuthnRequest(req),
		AuthorizationParameters: params,
	}
}

type PushedAuthorizationResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type DynamicClientRequest struct {
	Id string
	// This value is filled with the authorization header when creating a client with DCR.
	InitialAccessToken string
	// This value is filled with the authorization header for all DCM requests.
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

type OpenIdMtlsConfiguration struct {
	TokenEndpoint         string `json:"token_endpoint"`
	ParEndpoint           string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
}

type OpenIdConfiguration struct {
	Issuer                                         string                                 `json:"issuer"`
	ClientRegistrationEndpoint                     string                                 `json:"registration_endpoint"`
	AuthorizationEndpoint                          string                                 `json:"authorization_endpoint"`
	TokenEndpoint                                  string                                 `json:"token_endpoint"`
	UserinfoEndpoint                               string                                 `json:"userinfo_endpoint"`
	JwksEndpoint                                   string                                 `json:"jwks_uri"`
	ParEndpoint                                    string                                 `json:"pushed_authorization_request_endpoint,omitempty"`
	ParIsRequired                                  bool                                   `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                                  []goidc.ResponseType                   `json:"response_types_supported"`
	ResponseModes                                  []goidc.ResponseMode                   `json:"response_modes_supported"`
	GrantTypes                                     []goidc.GrantType                      `json:"grant_types_supported"`
	Scopes                                         []string                               `json:"scopes_supported"`
	UserClaimsSupported                            []string                               `json:"claims_supported"`
	UserClaimTypesSupported                        []goidc.ClaimType                      `json:"claim_types_supported,omitempty"`
	SubjectIdentifierTypes                         []goidc.SubjectIdentifierType          `json:"subject_types_supported"`
	IdTokenSignatureAlgorithms                     []jose.SignatureAlgorithm              `json:"id_token_signing_alg_values_supported"`
	IdTokenKeyEncryptionAlgorithms                 []jose.KeyAlgorithm                    `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenContentEncryptionAlgorithms             []jose.ContentEncryption               `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncryptionAlgorithms                []jose.KeyAlgorithm                    `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncryptionAlgorithms            []jose.ContentEncryption               `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSignatureAlgorithms                    []jose.SignatureAlgorithm              `json:"userinfo_signing_alg_values_supported"`
	ClientAuthnMethods                             []goidc.ClientAuthnType                `json:"token_endpoint_auth_methods_supported"`
	JarIsRequired                                  bool                                   `json:"require_signed_request_object,omitempty"`
	JarIsEnabled                                   bool                                   `json:"request_parameter_supported"`
	JarAlgorithms                                  []jose.SignatureAlgorithm              `json:"request_object_signing_alg_values_supported,omitempty"`
	JarKeyEncrytionAlgorithms                      []jose.KeyAlgorithm                    `json:"request_object_encryption_alg_values_supported,omitempty"`
	JarContentEncryptionAlgorithms                 []jose.ContentEncryption               `json:"request_object_encryption_enc_values_supported,omitempty"`
	JarmAlgorithms                                 []jose.SignatureAlgorithm              `json:"authorization_signing_alg_values_supported,omitempty"`
	JarmKeyEncryptionAlgorithms                    []jose.KeyAlgorithm                    `json:"authorization_encryption_alg_values_supported,omitempty"`
	JarmContentEncryptionAlgorithms                []jose.ContentEncryption               `json:"authorization_encryption_enc_values_supported,omitempty"`
	TokenEndpointClientSigningAlgorithms           []jose.SignatureAlgorithm              `json:"token_endpoint_auth_signing_alg_values_supported"`
	IssuerResponseParameterIsEnabled               bool                                   `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterIsEnabled                       bool                                   `json:"claims_parameter_supported"`
	AuthorizationDetailsIsSupported                bool                                   `json:"authorization_details_supported"`
	AuthorizationDetailTypesSupported              []string                               `json:"authorization_data_types_supported,omitempty"`
	DpopSignatureAlgorithms                        []jose.SignatureAlgorithm              `json:"dpop_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                          string                                 `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointClientAuthnMethods        []goidc.ClientAuthnType                `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointClientSignatureAlgorithms []jose.SignatureAlgorithm              `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	MtlsConfiguration                              OpenIdMtlsConfiguration                `json:"mtls_endpoint_aliases"`
	TlsBoundTokensIsEnabled                        bool                                   `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthenticationContextReferences                []goidc.AuthenticationContextReference `json:"acr_values_supported,omitempty"`
	DisplayValuesSupported                         []goidc.DisplayValue                   `json:"display_values_supported,omitempty"`
}

type Token struct {
	Id                    string
	Format                goidc.TokenFormat
	Value                 string
	Type                  goidc.TokenType
	JwkThumbprint         string
	CertificateThumbprint string
}

type RedirectParameters struct {
	Response          string
	Issuer            string
	AccessToken       string
	TokenType         goidc.TokenType
	IdToken           string
	AuthorizationCode string
	State             string
	Error             goidc.ErrorCode
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
	JwtClaims string
	Claims    map[string]any
}

type TokenIntrospectionRequest struct {
	ClientAuthnRequest
	Token         string
	TokenTypeHint goidc.TokenTypeHint
}

func NewTokenIntrospectionRequest(req *http.Request) TokenIntrospectionRequest {
	return TokenIntrospectionRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		Token:              req.PostFormValue("token"),
		TokenTypeHint:      goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

type TokenIntrospectionInfo struct {
	IsActive                    bool
	Scopes                      string
	AuthorizationDetails        []goidc.AuthorizationDetail
	ClientId                    string
	Subject                     string
	ExpiresAtTimestamp          int
	JwkThumbprint               string
	ClientCertificateThumbprint string
	AdditionalTokenClaims       map[string]any
}

func (info TokenIntrospectionInfo) MarshalJSON() ([]byte, error) {
	if !info.IsActive {
		return json.Marshal(map[string]any{
			"active": false,
		})
	}

	params := map[string]any{
		"active":            true,
		goidc.SubjectClaim:  info.Subject,
		goidc.ScopeClaim:    info.Scopes,
		goidc.ClientIdClaim: info.ClientId,
		goidc.ExpiryClaim:   info.ExpiresAtTimestamp,
	}

	if info.AuthorizationDetails != nil {
		params[goidc.AuthorizationDetailsClaim] = info.AuthorizationDetails
	}

	confirmation := make(map[string]string)
	if info.JwkThumbprint != "" {
		confirmation["jkt"] = info.JwkThumbprint
	}
	if info.ClientCertificateThumbprint != "" {
		confirmation["x5t#S256"] = info.ClientCertificateThumbprint
	}
	if len(confirmation) != 0 {
		params["cnf"] = confirmation
	}

	for k, v := range info.AdditionalTokenClaims {
		params[k] = v
	}

	return json.Marshal(params)
}
