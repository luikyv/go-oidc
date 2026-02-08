package discovery

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type OpenIDConfiguration struct {
	Issuer                              string                             `json:"issuer"`
	ClientRegistrationEndpoint          string                             `json:"registration_endpoint,omitempty"`
	AuthorizationEndpoint               string                             `json:"authorization_endpoint"`
	TokenEndpoint                       string                             `json:"token_endpoint"`
	UserinfoEndpoint                    string                             `json:"userinfo_endpoint"`
	JWKSEndpoint                        string                             `json:"jwks_uri,omitempty"`
	PAREndpoint                         string                             `json:"pushed_authorization_request_endpoint,omitempty"`
	PARIsRequired                       bool                               `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                       []goidc.ResponseType               `json:"response_types_supported,omitempty"`
	ResponseModes                       []goidc.ResponseMode               `json:"response_modes_supported,omitempty"`
	GrantTypes                          []goidc.GrantType                  `json:"grant_types_supported,omitempty"`
	Scopes                              []string                           `json:"scopes_supported"`
	UserClaimsSupported                 []string                           `json:"claims_supported,omitempty"`
	ClaimTypesSupported                 []goidc.ClaimType                  `json:"claim_types_supported,omitempty"`
	SubIdentifierTypes                  []goidc.SubIdentifierType          `json:"subject_types_supported,omitempty"`
	IDTokenSigAlgs                      []goidc.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncAlgs                   []goidc.KeyEncryptionAlgorithm     `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncAlgs               []goidc.ContentEncryptionAlgorithm `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncAlgs                  []goidc.KeyEncryptionAlgorithm     `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncAlgs              []goidc.ContentEncryptionAlgorithm `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSigAlgs                     []goidc.SignatureAlgorithm         `json:"userinfo_signing_alg_values_supported,omitempty"`
	TokenAuthnMethods                   []goidc.ClientAuthnType            `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthnSigAlgs                   []goidc.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	JARIsEnabled                        bool                               `json:"request_parameter_supported,omitempty"`
	JARIsRequired                       bool                               `json:"require_signed_request_object,omitempty"`
	JARAlgs                             []goidc.SignatureAlgorithm         `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncAlgs                       []goidc.KeyEncryptionAlgorithm     `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncAlgs                   []goidc.ContentEncryptionAlgorithm `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARByReferenceIsEnabled             bool                               `json:"request_uri_parameter_supported,omitempty"`
	JARRequestURIRegistrationIsRequired bool                               `json:"require_request_uri_registration,omitempty"`
	JARMAlgs                            []goidc.SignatureAlgorithm         `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncAlgs                      []goidc.KeyEncryptionAlgorithm     `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncAlgs                  []goidc.ContentEncryptionAlgorithm `json:"authorization_encryption_enc_values_supported,omitempty"`
	IssuerResponseParamIsEnabled        bool                               `json:"authorization_response_iss_parameter_supported,omitempty"`
	ClaimsParamIsEnabled                bool                               `json:"claims_parameter_supported,omitempty"`
	AuthDetailsIsEnabled                bool                               `json:"authorization_details_supported,omitempty"`
	AuthDetailTypesSupported            []string                           `json:"authorization_data_types_supported,omitempty"`
	DPoPSigAlgs                         []goidc.SignatureAlgorithm         `json:"dpop_signing_alg_values_supported,omitempty"`
	TokenIntrospectionEndpoint          string                             `json:"introspection_endpoint,omitempty"`
	TokenIntrospectionAuthnMethods      []goidc.ClientAuthnType            `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	TokenIntrospectionAuthnSigAlgs      []goidc.SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	TokenRevocationEndpoint             string                             `json:"revocation_endpoint,omitempty"`
	TokenRevocationAuthnMethods         []goidc.ClientAuthnType            `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	TokenRevocationAuthnSigAlgs         []goidc.SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	CIBATokenDeliveryModes []goidc.CIBATokenDeliveryMode `json:"backchannel_token_delivery_modes_supported,omitempty"`
	CIBAEndpoint           string                        `json:"backchannel_authentication_endpoint,omitempty"`
	CIBAJARSigAlgs         []goidc.SignatureAlgorithm    `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	CIBAUserCodeIsEnabled  bool                          `json:"backchannel_user_code_parameter_supported,omitempty"`

	MTLSConfig *openIDMTLSConfiguration `json:"mtls_endpoint_aliases,omitempty"`
	// TLSBoundTokensIsEnabled signals support for certificate bound tokens.
	TLSBoundTokensIsEnabled        bool                           `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	ACRs                           []goidc.ACR                    `json:"acr_values_supported,omitempty"`
	DisplayValues                  []goidc.DisplayValue           `json:"display_values_supported,omitempty"`
	CodeChallengeMethods           []goidc.CodeChallengeMethod    `json:"code_challenge_methods_supported,omitempty"`
	EndSessionEndpoint             string                         `json:"end_session_endpoint,omitempty"`
	ClientRegistrationTypes        []goidc.ClientRegistrationType `json:"client_registration_types_supported"`
	OrganizationName               string                         `json:"organization_name,omitempty"`
	FederationRegistrationEndpoint string                         `json:"federation_registration_endpoint,omitempty"`
	SignedJWKSEndpoint             string                         `json:"signed_jwks_uri,omitempty"`
	JWKS                           *goidc.JSONWebKeySet           `json:"jwks,omitempty"`
}

type openIDMTLSConfiguration struct {
	TokenEndpoint              string `json:"token_endpoint"`
	ParEndpoint                string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserinfoEndpoint           string `json:"userinfo_endpoint"`
	ClientRegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	TokenIntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	TokenRevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	CIBAEndpoint               string `json:"backchannel_authentication_endpoint,omitempty"`
}
