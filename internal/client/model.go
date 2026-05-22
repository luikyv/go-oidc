package client

import "github.com/luikyv/go-oidc/pkg/goidc"

var JSONFields = []string{
	"client_id",
	"client_name",
	"client_secret_expires_at",
	"application_type",
	"logo_uri",
	"contacts",
	"policy_uri",
	"tos_uri",
	"redirect_uris",
	"request_uris",
	"grant_types",
	"response_types",
	"jwks_uri",
	"jwks",
	"signed_jwks_uri",
	"scope",
	"subject_type",
	"sector_identifier_uri",
	"id_token_signed_response_alg",
	"id_token_encrypted_response_alg",
	"id_token_encrypted_response_enc",
	"userinfo_signed_response_alg",
	"userinfo_encrypted_response_alg",
	"userinfo_encrypted_response_enc",
	"require_signed_request_object",
	"request_object_signing_alg",
	"request_object_encryption_alg",
	"request_object_encryption_enc",
	"authorization_signed_response_alg",
	"authorization_encrypted_response_alg",
	"authorization_encrypted_response_enc",
	"token_endpoint_auth_method",
	"token_endpoint_auth_signing_alg",
	"introspection_endpoint_auth_method",
	"introspection_endpoint_auth_signing_alg",
	"revocation_endpoint_auth_method",
	"revocation_endpoint_auth_signing_alg",
	"dpop_bound_access_tokens",
	"tls_client_auth_subject_dn",
	"tls_client_auth_san_dns",
	"tls_client_auth_san_ip",
	"tls_client_certificate_bound_access_tokens",
	"authorization_details_types",
	"default_max_age",
	"default_acr_values",
	"require_pushed_authorization_requests",
	"backchannel_token_delivery_mode",
	"backchannel_client_notification_endpoint",
	"backchannel_authentication_request_signing_alg",
	"backchannel_user_code_parameter",
	"organization_name",
	"post_logout_redirect_uris",
	"client_registration_types",
	"display_name",
	"description",
	"keywords",
	"information_uri",
	"organization_uri",
	"credential_offer_endpoint",
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
	"id_token_encryption_alg_values_supported",
	"id_token_encryption_enc_values_supported",
	"userinfo_signing_alg_values_supported",
	"userinfo_encryption_alg_values_supported",
	"userinfo_encryption_enc_values_supported",
	"request_object_signing_alg_values_supported",
	"request_object_encryption_alg_values_supported",
	"request_object_encryption_enc_values_supported",
	"token_endpoint_auth_methods_supported",
	"token_endpoint_auth_signing_alg_values_supported",
	"backchannel_authentication_request_signing_alg_values_supported",
	"authorization_signing_alg_values_supported",
	"authorization_encryption_alg_values_supported",
	"authorization_encryption_enc_values_supported",
}

type Meta struct {
	SubIdentifierTypes     []goidc.SubIdentifierType          `json:"subject_types_supported,omitempty"`
	IDTokenSigAlgs         []goidc.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenKeyEncAlgs      []goidc.KeyEncryptionAlgorithm     `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncAlgs  []goidc.ContentEncryptionAlgorithm `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoSigAlgs        []goidc.SignatureAlgorithm         `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoKeyEncAlgs     []goidc.KeyEncryptionAlgorithm     `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncAlgs []goidc.ContentEncryptionAlgorithm `json:"userinfo_encryption_enc_values_supported,omitempty"`
	JARSigAlgs             []goidc.SignatureAlgorithm         `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncAlgs          []goidc.KeyEncryptionAlgorithm     `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncAlgs      []goidc.ContentEncryptionAlgorithm `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenAuthnMethods      []goidc.AuthnMethod                `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthnSigAlgs      []goidc.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	CIBAJARSigAlgs         []goidc.SignatureAlgorithm         `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	JARMSigAlgs            []goidc.SignatureAlgorithm         `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncAlgs         []goidc.KeyEncryptionAlgorithm     `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncAlgs     []goidc.ContentEncryptionAlgorithm `json:"authorization_encryption_enc_values_supported,omitempty"`
	// `json:"introspection_signing_alg_values_supported,omitempty"`
	// `json:"introspection_encryption_alg_values_supported,omitempty"`
	// `json:"introspection_encryption_enc_values_supported,omitempty"`
	goidc.ClientMeta
}
