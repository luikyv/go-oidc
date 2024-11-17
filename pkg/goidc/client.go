package goidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4"
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
	// HashedRegistrationAccessToken is the hash of the registration access token
	// generated during dynamic client registration.
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token"`
	ClientMetaInfo
}

func (c *Client) IsPublic() bool {
	return c.TokenAuthnMethod == ClientAuthnNone
}

// FetchPublicJWKS fetches the client public JWKS either directly from the jwks
// attribute or using jwks_uri.
//
// This function also caches the keys if they are fetched from jwks_uri.
func (c *Client) FetchPublicJWKS(httpClient *http.Client) (jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet

	if c.PublicJWKS != nil {
		err := json.Unmarshal(c.PublicJWKS, &jwks)
		return jwks, err
	}

	if c.PublicJWKSURI == "" {
		return jose.JSONWebKeySet{},
			errors.New("the client jwks was informed neither by value nor by reference")
	}

	rawJWKS, err := c.fetchJWKS(httpClient)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	// Cache the client JWKS.
	c.PublicJWKS = rawJWKS

	err = json.Unmarshal(c.PublicJWKS, &jwks)
	return jwks, err
}

func (c *Client) fetchJWKS(httpClient *http.Client) (json.RawMessage, error) {
	resp, err := httpClient.Get(c.PublicJWKSURI)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, WrapError(ErrorCodeInvalidClientMetadata, "could not fetch client jwks", err)
	}

	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

type ClientMetaInfo struct {
	Name            string          `json:"client_name,omitempty"`
	ApplicationType ApplicationType `json:"application_type,omitempty"`
	LogoURI         string          `json:"logo_uri,omitempty"`
	Contacts        []string        `json:"contacts,omitempty"`
	RedirectURIs    []string        `json:"redirect_uris,omitempty"`
	RequestURIs     []string        `json:"request_uris,omitempty"`
	GrantTypes      []GrantType     `json:"grant_types"`
	ResponseTypes   []ResponseType  `json:"response_types"`
	PublicJWKSURI   string          `json:"jwks_uri,omitempty"`
	PublicJWKS      json.RawMessage `json:"jwks,omitempty"`
	// ScopeIDs contains the scopes available to the client separeted by spaces.
	ScopeIDs              string                  `json:"scope,omitempty"`
	SubIdentifierType     SubIdentifierType       `json:"subject_type,omitempty"`
	SectorIdentifierURI   string                  `json:"sector_identifier_uri,omitempty"`
	IDTokenSigAlg         jose.SignatureAlgorithm `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg      jose.KeyAlgorithm       `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg  jose.ContentEncryption  `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg        jose.SignatureAlgorithm `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg     jose.KeyAlgorithm       `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg jose.ContentEncryption  `json:"userinfo_encrypted_response_enc,omitempty"`
	JARIsRequired         bool                    `json:"require_signed_request_object,omitempty"`
	// TODO: Is JAR required if this is informed?
	JARSigAlg                     jose.SignatureAlgorithm `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  jose.KeyAlgorithm       `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              jose.ContentEncryption  `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    jose.SignatureAlgorithm `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 jose.KeyAlgorithm       `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             jose.ContentEncryption  `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              ClientAuthnType         `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod ClientAuthnType         `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg jose.SignatureAlgorithm `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    ClientAuthnType         `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    jose.SignatureAlgorithm `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    bool                    `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       string                  `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubAlternativeName represents a DNS name.
	TLSSubAlternativeName     string                  `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp   string                  `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired bool                    `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes           []string                `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs         *int                    `json:"default_max_age,omitempty"`
	DefaultACRValues          string                  `json:"default_acr_values,omitempty"`
	PARIsRequired             bool                    `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode     CIBATokenDeliveryMode   `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint  string                  `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg             jose.SignatureAlgorithm `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled     bool                    `json:"backchannel_user_code_parameter,omitempty"`
	// CustomAttributes holds any additional dynamic attributes a client may
	// provide during registration.
	// These attributes allow clients to extend their metadata beyond the
	// predefined fields (e.g., client_name, logo_uri).
	// During DCR, any attributes that are not explicitly defined in the struct
	// will be captured here.
	// These additional fields are **flattened** in the DCR response, meaning
	// they are merged directly into the JSON response alongside standard fields.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}

func (c *ClientMetaInfo) SetAttribute(key string, value any) {
	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	c.CustomAttributes[key] = value
}

func (c *ClientMetaInfo) Attribute(key string) any {
	return c.CustomAttributes[key]
}
