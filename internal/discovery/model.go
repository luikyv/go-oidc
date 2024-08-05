package discovery

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type openIDConfiguration struct {
	Issuer                                         string                        `json:"issuer"`
	ClientRegistrationEndpoint                     string                        `json:"registration_endpoint,omitempty"`
	AuthorizationEndpoint                          string                        `json:"authorization_endpoint"`
	TokenEndpoint                                  string                        `json:"token_endpoint"`
	UserinfoEndpoint                               string                        `json:"userinfo_endpoint"`
	JWKSEndpoint                                   string                        `json:"jwks_uri"`
	ParEndpoint                                    string                        `json:"pushed_authorization_request_endpoint,omitempty"`
	PARIsRequired                                  bool                          `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                                  []goidc.ResponseType          `json:"response_types_supported"`
	ResponseModes                                  []goidc.ResponseMode          `json:"response_modes_supported"`
	GrantTypes                                     []goidc.GrantType             `json:"grant_types_supported"`
	Scopes                                         []string                      `json:"scopes_supported"`
	UserClaimsSupported                            []string                      `json:"claims_supported"`
	ClaimTypesSupported                            []goidc.ClaimType             `json:"claim_types_supported,omitempty"`
	SubjectIdentifierTypes                         []goidc.SubjectIdentifierType `json:"subject_types_supported"`
	IDTokenSignatureAlgorithms                     []jose.SignatureAlgorithm     `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncryptionAlgorithms                 []jose.KeyAlgorithm           `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncryptionAlgorithms             []jose.ContentEncryption      `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncryptionAlgorithms                []jose.KeyAlgorithm           `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncryptionAlgorithms            []jose.ContentEncryption      `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSignatureAlgorithms                    []jose.SignatureAlgorithm     `json:"userinfo_signing_alg_values_supported"`
	ClientAuthnMethods                             []goidc.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
	JARIsRequired                                  bool                          `json:"require_signed_request_object,omitempty"`
	JARIsEnabled                                   bool                          `json:"request_parameter_supported"`
	JARAlgorithms                                  []jose.SignatureAlgorithm     `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncrytionAlgorithms                      []jose.KeyAlgorithm           `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncryptionAlgorithms                 []jose.ContentEncryption      `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARMAlgorithms                                 []jose.SignatureAlgorithm     `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncryptionAlgorithms                    []jose.KeyAlgorithm           `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncryptionAlgorithms                []jose.ContentEncryption      `json:"authorization_encryption_enc_values_supported,omitempty"`
	TokenEndpointClientSigningAlgorithms           []jose.SignatureAlgorithm     `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	IssuerResponseParameterIsEnabled               bool                          `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterIsEnabled                       bool                          `json:"claims_parameter_supported"`
	AuthorizationDetailsIsSupported                bool                          `json:"authorization_details_supported"`
	AuthorizationDetailTypesSupported              []string                      `json:"authorization_data_types_supported,omitempty"`
	DPoPSignatureAlgorithms                        []jose.SignatureAlgorithm     `json:"dpop_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                          string                        `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointClientAuthnMethods        []goidc.ClientAuthnType       `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointClientSignatureAlgorithms []jose.SignatureAlgorithm     `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	MTLSConfiguration                              *openIDMTLSConfiguration      `json:"mtls_endpoint_aliases,omitempty"`
	TLSBoundTokensIsEnabled                        bool                          `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthenticationContextReferences                []goidc.ACR                   `json:"acr_values_supported,omitempty"`
	DisplayValuesSupported                         []goidc.DisplayValue          `json:"display_values_supported,omitempty"`
}

type openIDMTLSConfiguration struct {
	TokenEndpoint              string `json:"token_endpoint"`
	ParEndpoint                string `json:"pushed_authorization_request_endpoint,omitempty"`
	UserinfoEndpoint           string `json:"userinfo_endpoint"`
	ClientRegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint      string `json:"introspection_endpoint,omitempty"`
}
