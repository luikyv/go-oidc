package discovery

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type openIDConfiguration struct {
	Issuer                              string                        `json:"issuer"`
	ClientRegistrationEndpoint          string                        `json:"registration_endpoint,omitempty"`
	AuthorizationEndpoint               string                        `json:"authorization_endpoint"`
	TokenEndpoint                       string                        `json:"token_endpoint"`
	UserinfoEndpoint                    string                        `json:"userinfo_endpoint"`
	JWKSEndpoint                        string                        `json:"jwks_uri"`
	PAREndpoint                         string                        `json:"pushed_authorization_request_endpoint,omitempty"`
	PARIsRequired                       bool                          `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                       []goidc.ResponseType          `json:"response_types_supported,omitempty"`
	ResponseModes                       []goidc.ResponseMode          `json:"response_modes_supported,omitempty"`
	GrantTypes                          []goidc.GrantType             `json:"grant_types_supported"`
	Scopes                              []string                      `json:"scopes_supported"`
	UserClaimsSupported                 []string                      `json:"claims_supported,omitempty"`
	ClaimTypesSupported                 []goidc.ClaimType             `json:"claim_types_supported,omitempty"`
	SubIdentifierTypes                  []goidc.SubjectIdentifierType `json:"subject_types_supported,omitempty"`
	IDTokenSigAlgs                      []jose.SignatureAlgorithm     `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncAlgs                   []jose.KeyAlgorithm           `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncAlgs               []jose.ContentEncryption      `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncAlgs                  []jose.KeyAlgorithm           `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncAlgs              []jose.ContentEncryption      `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSigAlgs                     []jose.SignatureAlgorithm     `json:"userinfo_signing_alg_values_supported"`
	TokenAuthnMethods                   []goidc.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
	TokenAuthnSigAlgs                   []jose.SignatureAlgorithm     `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	JARIsEnabled                        bool                          `json:"request_parameter_supported,omitempty"`
	JARIsRequired                       bool                          `json:"require_signed_request_object,omitempty"`
	JARAlgs                             []jose.SignatureAlgorithm     `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncAlgs                       []jose.KeyAlgorithm           `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncAlgs                   []jose.ContentEncryption      `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARByReferenceIsEnabled             bool                          `json:"request_uri_parameter_supported,omitempty"`
	JARRequestURIRegistrationIsRequired bool                          `json:"require_request_uri_registration,omitempty"`
	JARMAlgs                            []jose.SignatureAlgorithm     `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncAlgs                      []jose.KeyAlgorithm           `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncAlgs                  []jose.ContentEncryption      `json:"authorization_encryption_enc_values_supported,omitempty"`
	IssuerResponseParamIsEnabled        bool                          `json:"authorization_response_iss_parameter_supported"`
	ClaimsParamIsEnabled                bool                          `json:"claims_parameter_supported"`
	AuthDetailsIsEnabled                bool                          `json:"authorization_details_supported"`
	AuthDetailTypesSupported            []string                      `json:"authorization_data_types_supported,omitempty"`
	DPoPSigAlgs                         []jose.SignatureAlgorithm     `json:"dpop_signing_alg_values_supported,omitempty"`
	TokenIntrospectionEndpoint          string                        `json:"introspection_endpoint,omitempty"`
	TokenIntrospectionAuthnMethods      []goidc.ClientAuthnType       `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	TokenIntrospectionAuthnSigAlgs      []jose.SignatureAlgorithm     `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	TokenRevocationEndpoint             string                        `json:"revocation_endpoint,omitempty"`
	TokenRevocationAuthnMethods         []goidc.ClientAuthnType       `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	TokenRevocationAuthnSigAlgs         []jose.SignatureAlgorithm     `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	MTLSConfig                          *openIDMTLSConfiguration      `json:"mtls_endpoint_aliases,omitempty"`
	// TLSBoundTokensIsEnabled signals support for certificate bound tokens.
	TLSBoundTokensIsEnabled bool                        `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	ACRs                    []goidc.ACR                 `json:"acr_values_supported,omitempty"`
	DisplayValues           []goidc.DisplayValue        `json:"display_values_supported,omitempty"`
	CodeChallengeMethods    []goidc.CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}

type openIDMTLSConfiguration struct {
	TokenEndpoint              string `json:"token_endpoint"`
	ParEndpoint                string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserinfoEndpoint           string `json:"userinfo_endpoint"`
	ClientRegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint      string `json:"introspection_endpoint,omitempty"`
}
