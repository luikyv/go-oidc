package goidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ClientManager gathers all the logic needed to manage clients.
type ClientManager interface {
	Save(ctx context.Context, client *Client) error
	Client(ctx context.Context, id string) (*Client, error)
	Delete(ctx context.Context, id string) error
}

// Client contains all information about an OAuth client.
type Client struct {
	ID string `json:"client_id"`
	// Secret is used when the client authenticates with client_secret_jwt,
	// since the key used to sign the assertion is the same used to verify it.
	Secret string `json:"client_secret,omitempty"`
	// HashedSecret is the hash of the client secret for the client_secret_basic
	// and client_secret_post authentication methods.
	HashedSecret string `json:"hashed_secret,omitempty"`
	// HashedRegistrationToken is the thumbprint of the registration access token
	// generated during dynamic client registration.
	HashedRegistrationToken string `json:"hashed_registration_token,omitempty"`
	ExpiresAt               *int   `json:"expires_at,omitempty"`

	IsFederated      bool                   `json:"is_federated"`
	RegistrationType ClientRegistrationType `json:"registration_type,omitempty"`
	TrustMarkIDs     []string               `json:"trust_mark_ids,omitempty"`
	ClientMeta
}

func (c *Client) IsPublic() bool {
	return c.TokenAuthnMethod == ClientAuthnNone
}

// FetchPublicJWKS fetches the client public JWKS either directly from the jwks
// attribute or using jwks_uri.
//
// This function also caches the keys if they are fetched from jwks_uri.
func (c *Client) FetchPublicJWKS(httpClient *http.Client) (JSONWebKeySet, error) {
	if c.PublicJWKS.Keys != nil {
		return c.PublicJWKS, nil
	}

	if c.PublicSignedJWKSURI != "" {
		return c.fetchSignedJWKS(httpClient)
	}

	if c.PublicJWKSURI == "" {
		return JSONWebKeySet{}, errors.New("the client jwks was informed neither by value nor by reference")
	}

	jwks, err := c.fetchJWKS(httpClient)
	if err != nil {
		return JSONWebKeySet{}, err
	}
	// Cache the client JWKS.
	c.PublicJWKS = jwks

	return jwks, err
}

func (c *Client) fetchJWKS(httpClient *http.Client) (JSONWebKeySet, error) {
	resp, err := httpClient.Get(c.PublicJWKSURI)
	if err != nil {
		return JSONWebKeySet{}, WrapError(ErrorCodeInvalidClientMetadata, "could not fetch the client jwks", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JSONWebKeySet{}, WrapError(ErrorCodeInvalidClientMetadata, fmt.Sprintf("fetching the client jwks resulted in %d", resp.StatusCode), err)
	}

	var jwks JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return JSONWebKeySet{}, WrapError(ErrorCodeInvalidClientMetadata, "could not parse the client jwks", err)
	}

	return jwks, nil
}

// TODO.
func (c *Client) fetchSignedJWKS(_ *http.Client) (JSONWebKeySet, error) {
	return JSONWebKeySet{}, errors.ErrUnsupported
}

type ClientMeta struct {
	Name              string          `json:"client_name,omitempty"`
	ApplicationType   ApplicationType `json:"application_type,omitempty"`
	LogoURI           string          `json:"logo_uri,omitempty"`
	Contacts          []string        `json:"contacts,omitempty"`
	PolicyURI         string          `json:"policy_uri,omitempty"`
	TermsOfServiceURI string          `json:"tos_uri,omitempty"`
	RedirectURIs      []string        `json:"redirect_uris,omitempty"`
	RequestURIs       []string        `json:"request_uris,omitempty"`
	GrantTypes        []GrantType     `json:"grant_types"`
	ResponseTypes     []ResponseType  `json:"response_types"`
	PublicJWKSURI     string          `json:"jwks_uri,omitempty"`
	PublicJWKS        JSONWebKeySet   `json:"jwks,omitempty"`
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
	TokenAuthnMethod              ClientAuthnType            `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod ClientAuthnType            `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    ClientAuthnType            `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    bool                       `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       string                     `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubAlternativeName represents a DNS name.
	TLSSubAlternativeName     string                `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp   string                `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired bool                  `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes           []string              `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs         *int                  `json:"default_max_age,omitempty"`
	DefaultACRValues          string                `json:"default_acr_values,omitempty"`
	PARIsRequired             bool                  `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode     CIBATokenDeliveryMode `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint  string                `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg             SignatureAlgorithm    `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled     bool                  `json:"backchannel_user_code_parameter,omitempty"`
	PublicSignedJWKSURI       string                `json:"signed_jwks_uri,omitempty"`
	OrganizationName          string                `json:"organization_name,omitempty"`
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

func (c *ClientMeta) SetCustomAttribute(key string, value any) {
	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	c.CustomAttributes[key] = value
}

func (c *ClientMeta) CustomAttribute(key string) any {
	return c.CustomAttributes[key]
}
