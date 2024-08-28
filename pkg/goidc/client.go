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
	Get(ctx context.Context, id string) (*Client, error)
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

// SetAttribute sets a custom attribute.
func (c *Client) SetAttribute(key string, value any) {
	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	c.CustomAttributes[key] = value
}

func (c *Client) Attribute(key string) any {
	return c.CustomAttributes[key]
}

// FetchPublicJWKS fetches the client public JWKS either directly from the jwks
// attribute or using jwks_uri.
// This method also caches the keys if they are fetched from jwks_uri.
func (c *Client) FetchPublicJWKS() (jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet

	if c.PublicJWKS != nil {
		err := json.Unmarshal(c.PublicJWKS, &jwks)
		return jwks, err
	}

	if c.PublicJWKSURI == "" {
		return jose.JSONWebKeySet{},
			errors.New("the client jwks was informed neither by value nor by reference")
	}

	rawJWKS, err := c.fetchJWKS()
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	// Cache the client JWKS.
	c.PublicJWKS = rawJWKS

	err = json.Unmarshal(c.PublicJWKS, &jwks)
	return jwks, err
}

func (c *Client) fetchJWKS() (json.RawMessage, error) {
	resp, err := http.Get(c.PublicJWKSURI)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("could not fetch client jwks")
	}

	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

type ClientMetaInfo struct {
	Name                    string                  `json:"client_name,omitempty"`
	LogoURI                 string                  `json:"logo_uri,omitempty"`
	RedirectURIs            []string                `json:"redirect_uris"`
	GrantTypes              []GrantType             `json:"grant_types"`
	ResponseTypes           []ResponseType          `json:"response_types"`
	PublicJWKSURI           string                  `json:"jwks_uri,omitempty"`
	PublicJWKS              json.RawMessage         `json:"jwks,omitempty"`
	Scopes                  string                  `json:"scope"`
	SubIdentifierType       SubjectIdentifierType   `json:"subject_type,omitempty"`
	IDTokenSigAlg           jose.SignatureAlgorithm `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg        jose.KeyAlgorithm       `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg    jose.ContentEncryption  `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg          jose.SignatureAlgorithm `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg       jose.KeyAlgorithm       `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg   jose.ContentEncryption  `json:"userinfo_encrypted_response_enc,omitempty"`
	JARSigAlg               jose.SignatureAlgorithm `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg            jose.KeyAlgorithm       `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg        jose.ContentEncryption  `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg              jose.SignatureAlgorithm `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg           jose.KeyAlgorithm       `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg       jose.ContentEncryption  `json:"authorization_encrypted_response_enc,omitempty"`
	AuthnMethod             ClientAuthnType         `json:"token_endpoint_auth_method"`
	AuthnSigAlg             jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg,omitempty"`
	DPoPIsRequired          bool                    `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName string                  `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubAlternativeName represents a DNS name.
	TLSSubAlternativeName   string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp string   `json:"tls_client_auth_san_ip,omitempty"`
	AuthDetailTypes         []string `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs       *int     `json:"default_max_age,omitempty"`
	DefaultACRValues        string   `json:"default_acr_values,omitempty"`
	// CustomAttributes holds any additional attributes a client has.
	// This field is flattened for DCR responses.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}
