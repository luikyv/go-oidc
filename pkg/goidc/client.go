package goidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/bcrypt"
)

// ClientManager contains all the logic needed to manage clients.
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

func (c *Client) PublicKey(keyID string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, errors.New("invalid key ID")
	}

	return keys[0], nil
}

func (c *Client) JARMEncryptionJWK() (jose.JSONWebKey, error) {
	return c.encryptionJWK(c.JARMKeyEncryptionAlgorithm)
}

func (c *Client) UserInfoEncryptionJWK() (jose.JSONWebKey, error) {
	return c.encryptionJWK(c.UserInfoKeyEncryptionAlgorithm)
}

func (c *Client) IDTokenEncryptionJWK() (jose.JSONWebKey, error) {
	return c.encryptionJWK(c.IDTokenKeyEncryptionAlgorithm)
}

// SignatureJWK returns the signature JWK based on the algorithm.
func (c *Client) SignatureJWK(algorithm jose.SignatureAlgorithm) (jose.JSONWebKey, error) {
	jwk, err := c.jwk(string(algorithm))
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if jwk.Use != string(KeyUsageSignature) {
		return jose.JSONWebKey{}, errors.New("invalid key usege")
	}

	return jwk, nil
}

// encryptionJWK returns the encryption JWK based on the algorithm.
func (c *Client) encryptionJWK(algorithm jose.KeyAlgorithm) (jose.JSONWebKey, error) {
	jwk, err := c.jwk(string(algorithm))
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if jwk.Use != string(KeyUsageEncryption) {
		return jose.JSONWebKey{}, errors.New("invalid key usege")
	}

	return jwk, nil
}

// jwk returns a client JWK based on the algorithm.
func (c *Client) jwk(algorithm string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == algorithm {
			return jwk, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", algorithm)
}

func (c *Client) AreScopesAllowed(
	availableScopes []Scope,
	requestedScopes string,
) bool {
	if requestedScopes == "" {
		return true
	}

	// Filter the client scopes that are available.
	var clientScopes []Scope
	for _, scope := range availableScopes {
		if strings.Contains(c.Scopes, scope.ID) {
			clientScopes = append(clientScopes, scope)
		}
	}

	// For each scope requested, make sure it matches one of the available
	// client scopes.
	for _, requestedScope := range strings.Split(requestedScopes, " ") {
		matches := false
		for _, scope := range clientScopes {
			if scope.Matches(requestedScope) {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	return true
}

func (c *Client) IsResponseTypeAllowed(responseType ResponseType) bool {
	return slices.Contains(c.ResponseTypes, responseType)
}

func (c *Client) IsGrantTypeAllowed(grantType GrantType) bool {
	return slices.Contains(c.GrantTypes, grantType)
}

func (c *Client) IsRedirectURIAllowed(redirectURI string) bool {
	for _, ru := range c.RedirectURIS {
		if redirectURI == ru {
			return true
		}
	}
	return false
}

func (c *Client) IsAuthorizationDetailTypeAllowed(authDetailType string) bool {
	// If the client didn't announce the authorization types it will use,
	// consider any value valid.
	if c.AuthorizationDetailTypes == nil {
		return true
	}

	return slices.Contains(c.AuthorizationDetailTypes, authDetailType)
}

func (c *Client) IsRegistrationAccessTokenValid(token string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(c.HashedRegistrationAccessToken), []byte(token))
	return err == nil
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
			errors.New("the client jwks was informed neither by value or by reference")
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
	Name                               string                  `json:"client_name,omitempty"`
	LogoURI                            string                  `json:"logo_uri,omitempty"`
	RedirectURIS                       []string                `json:"redirect_uris"`
	GrantTypes                         []GrantType             `json:"grant_types"`
	ResponseTypes                      []ResponseType          `json:"response_types"`
	PublicJWKSURI                      string                  `json:"jwks_uri,omitempty"`
	PublicJWKS                         json.RawMessage         `json:"jwks,omitempty"`
	Scopes                             string                  `json:"scope"`
	SubjectIdentifierType              SubjectIdentifierType   `json:"subject_type,omitempty"`
	IDTokenSignatureAlgorithm          jose.SignatureAlgorithm `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncryptionAlgorithm      jose.KeyAlgorithm       `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncryptionAlgorithm  jose.ContentEncryption  `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignatureAlgorithm         jose.SignatureAlgorithm `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncryptionAlgorithm     jose.KeyAlgorithm       `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncryptionAlgorithm jose.ContentEncryption  `json:"userinfo_encrypted_response_enc,omitempty"`
	JARSignatureAlgorithm              jose.SignatureAlgorithm `json:"request_object_signing_alg,omitempty"`
	JARKeyEncryptionAlgorithm          jose.KeyAlgorithm       `json:"request_object_encryption_alg,omitempty"`
	JARContentEncryptionAlgorithm      jose.ContentEncryption  `json:"request_object_encryption_enc,omitempty"`
	JARMSignatureAlgorithm             jose.SignatureAlgorithm `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncryptionAlgorithm         jose.KeyAlgorithm       `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncryptionAlgorithm     jose.ContentEncryption  `json:"authorization_encrypted_response_enc,omitempty"`
	AuthnMethod                        ClientAuthnType         `json:"token_endpoint_auth_method"`
	AuthnSignatureAlgorithm            jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg,omitempty"`
	DPoPIsRequired                     bool                    `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubjectDistinguishedName        string                  `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubjectAlternativeName represents a DNS name.
	TLSSubjectAlternativeName   string   `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubjectAlternativeNameIp string   `json:"tls_client_auth_san_ip,omitempty"`
	AuthorizationDetailTypes    []string `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs           *int     `json:"default_max_age,omitempty"`
	DefaultACRValues            string   `json:"default_acr_values,omitempty"`
	// CustomAttributes holds any additional attributes a client has.
	// This field is flattened for DCR responses.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}
