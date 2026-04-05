package goidc

import (
	"context"
)

// ClientManager gathers all the logic needed to manage clients.
type ClientManager interface {
	Save(ctx context.Context, client *Client) error
	Client(ctx context.Context, id string) (*Client, error)
	Delete(ctx context.Context, id string) error
}

type Client struct {
	ID     string `json:"id"`
	Secret string `json:"secret,omitempty"`
	// RegistrationToken is the plain text registration access token generated during
	// dynamic client registration.
	// Note: For security reasons, it is strongly recommended encrypt this value before storing it in a database.
	RegistrationToken  string `json:"registration_token,omitempty"`
	CreatedAtTimestamp int    `json:"created_at,omitempty"`
	ExpiresAtTimestamp int    `json:"expires_at,omitempty"`
	Federation         *struct {
		TrustAnchor string   `json:"trust_anchor"`
		TrustMarks  []string `json:"trust_marks,omitempty"`
	} `json:"federation,omitempty"`
	cachedJWKS *JSONWebKeySet
	ClientMeta
}

func (c *Client) IsPublic() bool {
	return c.TokenAuthnMethod == AuthnMethodNone
}

func (c *Client) CachedJWKS() *JSONWebKeySet {
	return c.cachedJWKS
}

func (c *Client) CacheJWKS(jwks *JSONWebKeySet) {
	c.cachedJWKS = jwks
}

type ClientMeta struct {
	Name              string          `json:"client_name,omitempty"`
	SecretExpiresAt   *int            `json:"client_secret_expires_at,omitempty"`
	ApplicationType   ApplicationType `json:"application_type,omitempty"`
	LogoURI           string          `json:"logo_uri,omitempty"`
	Contacts          []string        `json:"contacts,omitempty"`
	PolicyURI         string          `json:"policy_uri,omitempty"`
	TermsOfServiceURI string          `json:"tos_uri,omitempty"`
	RedirectURIs      []string        `json:"redirect_uris,omitempty"`
	RequestURIs       []string        `json:"request_uris,omitempty"`
	GrantTypes        []GrantType     `json:"grant_types"`
	ResponseTypes     []ResponseType  `json:"response_types"`
	JWKSURI           string          `json:"jwks_uri,omitempty"`
	JWKS              *JSONWebKeySet  `json:"jwks,omitempty"`
	SignedJWKSURI     string          `json:"signed_jwks_uri,omitempty"`
	// ScopeIDs contains the scopes available to the client separeted by spaces.
	ScopeIDs              string                     `json:"scope,omitempty"`
	SubIdentifierType     SubIdentifierType          `json:"subject_type,omitempty"`
	SectorIdentifierURI   string                     `json:"sector_identifier_uri,omitempty"`
	IDTokenSigAlg         SignatureAlgorithm         `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg      KeyEncryptionAlgorithm     `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg  ContentEncryptionAlgorithm `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg        SignatureAlgorithm         `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg     KeyEncryptionAlgorithm     `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg ContentEncryptionAlgorithm `json:"userinfo_encrypted_response_enc,omitempty"`
	JARIsRequired         bool                       `json:"require_signed_request_object,omitempty"`
	// TODO: Is JAR required if this is informed?
	JARSigAlg                     SignatureAlgorithm         `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  KeyEncryptionAlgorithm     `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              ContentEncryptionAlgorithm `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    SignatureAlgorithm         `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 KeyEncryptionAlgorithm     `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             ContentEncryptionAlgorithm `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              AuthnMethod                `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod AuthnMethod                `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    AuthnMethod                `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    bool                       `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       string                     `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubAlternativeName represents a DNS name.
	TLSSubAlternativeName     string                   `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp   string                   `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired bool                     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes           []AuthDetailType         `json:"authorization_details_types,omitempty"`
	DefaultMaxAgeSecs         *int                     `json:"default_max_age,omitempty"`
	DefaultACRValues          string                   `json:"default_acr_values,omitempty"`
	PARIsRequired             bool                     `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode     CIBATokenDeliveryMode    `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint  string                   `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg             SignatureAlgorithm       `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled     bool                     `json:"backchannel_user_code_parameter,omitempty"`
	OrganizationName          string                   `json:"organization_name,omitempty"`
	PostLogoutRedirectURIs    []string                 `json:"post_logout_redirect_uris,omitempty"`
	ClientRegistrationTypes   []ClientRegistrationType `json:"client_registration_types,omitempty"`
	DisplayName               string                   `json:"display_name,omitempty"`
	Description               string                   `json:"description,omitempty"`
	Keywords                  []string                 `json:"keywords,omitempty"`
	InformationURI            string                   `json:"information_uri,omitempty"`
	OrganizationURI           string                   `json:"organization_uri,omitempty"`
	CredentialOfferEndpoint   string                   `json:"credential_offer_endpoint,omitempty"`
	// CustomAttributes holds any additional dynamic attributes a client may
	// provide during registration.
	// These attributes allow clients to extend their metadata beyond the
	// predefined fields (e.g., client_name, logo_uri).
	// During DCR, any attributes that are not explicitly defined in the struct
	// will be captured here.
	// These additional fields are flattened in the DCR response, meaning
	// they are merged directly into the JSON response alongside standard fields.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}
