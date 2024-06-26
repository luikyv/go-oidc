package utils

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type DPOPJWTClaims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

type DPOPJWTValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
}

type ClientAuthnRequest struct {
	// The client ID sent via form is not specific to authentication. It is also a param for /authorize.
	ClientID            string
	ClientSecret        string
	ClientAssertionType goidc.ClientAssertionType
	ClientAssertion     string
}

func NewClientAuthnRequest(req *http.Request) ClientAuthnRequest {
	return ClientAuthnRequest{
		ClientID:            req.PostFormValue("client_id"),
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
	RedirectURI       string
	RefreshToken      string
	CodeVerifier      string
}

func NewTokenRequest(req *http.Request) TokenRequest {
	return TokenRequest{
		ClientAuthnRequest: NewClientAuthnRequest(req),
		GrantType:          goidc.GrantType(req.PostFormValue("grant_type")),
		Scopes:             req.PostFormValue("scope"),
		AuthorizationCode:  req.PostFormValue("code"),
		RedirectURI:        req.PostFormValue("redirect_uri"),
		RefreshToken:       req.PostFormValue("refresh_token"),
		CodeVerifier:       req.PostFormValue("code_verifier"),
	}
}

type TokenResponse struct {
	AccessToken          string                      `json:"access_token"`
	IDToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int                         `json:"expires_in"`
	TokenType            goidc.TokenType             `json:"token_type"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
}

type AuthorizationRequest struct {
	ClientID string `json:"client_id"`
	goidc.AuthorizationParameters
}

func NewAuthorizationRequest(req *http.Request) AuthorizationRequest {
	params := AuthorizationRequest{
		ClientID: req.URL.Query().Get("client_id"),
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:          req.URL.Query().Get("request_uri"),
			RequestObject:       req.URL.Query().Get("request"),
			RedirectURI:         req.URL.Query().Get("redirect_uri"),
			ResponseMode:        goidc.ResponseMode(req.URL.Query().Get("response_mode")),
			ResponseType:        goidc.ResponseType(req.URL.Query().Get("response_type")),
			Scopes:              req.URL.Query().Get("scope"),
			State:               req.URL.Query().Get("state"),
			Nonce:               req.URL.Query().Get("nonce"),
			CodeChallenge:       req.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: goidc.CodeChallengeMethod(req.URL.Query().Get("code_challenge_method")),
			Prompt:              goidc.PromptType(req.URL.Query().Get("prompt")),
			Display:             goidc.DisplayValue(req.URL.Query().Get("display")),
			ACRValues:           req.URL.Query().Get("acr_values"),
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

type AuthorizationResponse struct {
	Response          string
	Issuer            string
	AccessToken       string
	TokenType         goidc.TokenType
	IDToken           string
	AuthorizationCode string
	State             string
	Error             goidc.ErrorCode
	ErrorDescription  string
}

func (rp AuthorizationResponse) GetParameters() map[string]string {
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
	if rp.IDToken != "" {
		params["id_token"] = rp.IDToken
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

type PushedAuthorizationRequest struct {
	ClientAuthnRequest
	goidc.AuthorizationParameters
}

func NewPushedAuthorizationRequest(req *http.Request) PushedAuthorizationRequest {
	params := goidc.AuthorizationParameters{
		RequestURI:          req.PostFormValue("request_uri"),
		RequestObject:       req.PostFormValue("request"),
		RedirectURI:         req.PostFormValue("redirect_uri"),
		ResponseMode:        goidc.ResponseMode(req.PostFormValue("response_mode")),
		ResponseType:        goidc.ResponseType(req.PostFormValue("response_type")),
		Scopes:              req.PostFormValue("scope"),
		State:               req.PostFormValue("state"),
		Nonce:               req.PostFormValue("nonce"),
		CodeChallenge:       req.PostFormValue("code_challenge"),
		CodeChallengeMethod: goidc.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
		Prompt:              goidc.PromptType(req.PostFormValue("prompt")),
		Display:             goidc.DisplayValue(req.PostFormValue("display")),
		ACRValues:           req.PostFormValue("acr_values"),
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
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type DynamicClientResponse struct {
	ID                      string `json:"client_id"`
	Secret                  string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationURI         string `json:"registration_client_uri"`
	goidc.ClientMetaInfo
}

type OpenIDMTLSConfiguration struct {
	TokenEndpoint         string `json:"token_endpoint"`
	ParEndpoint           string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
}

type OpenIDConfiguration struct {
	Issuer                                         string                                 `json:"issuer"`
	ClientRegistrationEndpoint                     string                                 `json:"registration_endpoint"`
	AuthorizationEndpoint                          string                                 `json:"authorization_endpoint"`
	TokenEndpoint                                  string                                 `json:"token_endpoint"`
	UserinfoEndpoint                               string                                 `json:"userinfo_endpoint"`
	JWKSEndpoint                                   string                                 `json:"jwks_uri"`
	ParEndpoint                                    string                                 `json:"pushed_authorization_request_endpoint,omitempty"`
	PARIsRequired                                  bool                                   `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                                  []goidc.ResponseType                   `json:"response_types_supported"`
	ResponseModes                                  []goidc.ResponseMode                   `json:"response_modes_supported"`
	GrantTypes                                     []goidc.GrantType                      `json:"grant_types_supported"`
	Scopes                                         []string                               `json:"scopes_supported"`
	UserClaimsSupported                            []string                               `json:"claims_supported"`
	UserClaimTypesSupported                        []goidc.ClaimType                      `json:"claim_types_supported,omitempty"`
	SubjectIDentifierTypes                         []goidc.SubjectIDentifierType          `json:"subject_types_supported"`
	IDTokenSignatureAlgorithms                     []jose.SignatureAlgorithm              `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncryptionAlgorithms                 []jose.KeyAlgorithm                    `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncryptionAlgorithms             []jose.ContentEncryption               `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncryptionAlgorithms                []jose.KeyAlgorithm                    `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncryptionAlgorithms            []jose.ContentEncryption               `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSignatureAlgorithms                    []jose.SignatureAlgorithm              `json:"userinfo_signing_alg_values_supported"`
	ClientAuthnMethods                             []goidc.ClientAuthnType                `json:"token_endpoint_auth_methods_supported"`
	JARIsRequired                                  bool                                   `json:"require_signed_request_object,omitempty"`
	JARIsEnabled                                   bool                                   `json:"request_parameter_supported"`
	JARAlgorithms                                  []jose.SignatureAlgorithm              `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncrytionAlgorithms                      []jose.KeyAlgorithm                    `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncryptionAlgorithms                 []jose.ContentEncryption               `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARMAlgorithms                                 []jose.SignatureAlgorithm              `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncryptionAlgorithms                    []jose.KeyAlgorithm                    `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncryptionAlgorithms                []jose.ContentEncryption               `json:"authorization_encryption_enc_values_supported,omitempty"`
	TokenEndpointClientSigningAlgorithms           []jose.SignatureAlgorithm              `json:"token_endpoint_auth_signing_alg_values_supported"`
	IssuerResponseParameterIsEnabled               bool                                   `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterIsEnabled                       bool                                   `json:"claims_parameter_supported"`
	AuthorizationDetailsIsSupported                bool                                   `json:"authorization_details_supported"`
	AuthorizationDetailTypesSupported              []string                               `json:"authorization_data_types_supported,omitempty"`
	DPOPSignatureAlgorithms                        []jose.SignatureAlgorithm              `json:"dpop_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                          string                                 `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointClientAuthnMethods        []goidc.ClientAuthnType                `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointClientSignatureAlgorithms []jose.SignatureAlgorithm              `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	MTLSConfiguration                              OpenIDMTLSConfiguration                `json:"mtls_endpoint_aliases"`
	TLSBoundTokensIsEnabled                        bool                                   `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthenticationContextReferences                []goidc.AuthenticationContextReference `json:"acr_values_supported,omitempty"`
	DisplayValuesSupported                         []goidc.DisplayValue                   `json:"display_values_supported,omitempty"`
}

type Token struct {
	ID                    string
	Format                goidc.TokenFormat
	Value                 string
	Type                  goidc.TokenType
	JWKThumbprint         string
	CertificateThumbprint string
}

type UserInfoResponse struct {
	JWTClaims string
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
	ClientID                    string
	Subject                     string
	ExpiresAtTimestamp          int
	JWKThumbprint               string
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
		goidc.ClientIDClaim: info.ClientID,
		goidc.ExpiryClaim:   info.ExpiresAtTimestamp,
	}

	if info.AuthorizationDetails != nil {
		params[goidc.AuthorizationDetailsClaim] = info.AuthorizationDetails
	}

	confirmation := make(map[string]string)
	if info.JWKThumbprint != "" {
		confirmation["jkt"] = info.JWKThumbprint
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

type IDTokenOptions struct {
	Subject                 string
	ClientID                string
	AdditionalIDTokenClaims map[string]any
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

func NewIDTokenOptions(grantOpts goidc.GrantOptions) IDTokenOptions {
	return IDTokenOptions{
		Subject:                 grantOpts.Subject,
		ClientID:                grantOpts.ClientID,
		AdditionalIDTokenClaims: grantOpts.AdditionalIDTokenClaims,
	}
}
