package goidc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID string `json:"client_id" bson:"_id"`
	// Secret is used when the client authenticates with client_secret_jwt,
	// since the key used to sign the assertion is the same used to verify it.
	Secret string `json:"client_secret,omitempty" bson:"client_secret,omitempty"`
	// HashedSecret is the hash of the client secret for the client_secret_basic
	// and client_secret_post authentication methods.
	HashedSecret                  string `json:"hashed_secret,omitempty" bson:"hashed_secret,omitempty"`
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token" bson:"hashed_registration_access_token"`
	ClientMetaInfo                `bson:"inline"`
}

func (c *Client) PublicKey(keyID string) (JSONWebKey, OAuthError) {
	jwks, oauthErr := c.FetchPublicJWKS()
	if oauthErr != nil {
		return JSONWebKey{}, NewOAuthError(ErrorCodeInvalidRequest, oauthErr.Error())
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return JSONWebKey{}, NewOAuthError(ErrorCodeInvalidClient, "invalid key ID")
	}

	return keys[0], nil
}

func (c *Client) JARMEncryptionJWK() (JSONWebKey, OAuthError) {
	return c.encryptionJWK(c.JARMKeyEncryptionAlgorithm)
}

func (c *Client) UserInfoEncryptionJWK() (JSONWebKey, OAuthError) {
	return c.encryptionJWK(c.UserInfoKeyEncryptionAlgorithm)
}

func (c *Client) IDTokenEncryptionJWK() (JSONWebKey, OAuthError) {
	return c.encryptionJWK(c.IDTokenKeyEncryptionAlgorithm)
}

// encryptionJWK returns the encryption JWK based on the algorithm.
func (c *Client) encryptionJWK(algorithm jose.KeyAlgorithm) (JSONWebKey, OAuthError) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return JSONWebKey{}, NewOAuthError(ErrorCodeInvalidRequest, err.Error())
	}

	for _, jwk := range jwks.Keys {
		if jwk.Usage() == string(KeyUsageEncryption) && jwk.Algorithm() == string(algorithm) {
			return jwk, nil
		}
	}

	return JSONWebKey{}, NewOAuthError(ErrorCodeInvalidClient, fmt.Sprintf("invalid key algorithm: %s", algorithm))
}

func (c *Client) AreScopesAllowed(ctx Context, availableScopes Scopes, requestedScopes string) bool {
	scopeIDs := SplitStringWithSpaces(c.Scopes)
	clientScopes := availableScopes.SubSet(scopeIDs)
	for _, requestedScope := range SplitStringWithSpaces(requestedScopes) {
		if !clientScopes.Contains(requestedScope) {
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
		if strings.HasPrefix(redirectURI, ru) {
			return true
		}
	}
	return false
}

func (c *Client) IsAuthorizationDetailTypeAllowed(authDetailType string) bool {
	// If the client didn't announce the authorization types it will use, consider any value valid.
	if c.AuthorizationDetailTypes == nil {
		return true
	}

	return slices.Contains(c.AuthorizationDetailTypes, authDetailType)
}

func (c *Client) IsRegistrationAccessTokenValid(token string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(c.HashedRegistrationAccessToken), []byte(token))
	return err == nil
}

// FetchPublicJWKS fetches the client public JWKS either directly from the jwks attribute or using jwks_uri.
// This method also caches the keys if they are fetched from jwks_uri.
func (c *Client) FetchPublicJWKS() (JSONWebKeySet, error) {
	if c.PublicJWKS != nil {
		return *c.PublicJWKS, nil
	}

	if c.PublicJWKSURI == "" {
		return JSONWebKeySet{}, NewOAuthError(ErrorCodeInvalidRequest, "The client JWKS was informed neither by value or by reference")
	}

	jwks, err := FetchJWKS(c.PublicJWKSURI)
	if err != nil {
		return JSONWebKeySet{}, NewOAuthError(ErrorCodeInvalidRequest, err.Error())
	}
	// Cache the client JWKS.
	c.PublicJWKS = &jwks

	return jwks, nil
}

// Function that will be executed during DCR and DCM.
// It can be used to modify the client and perform custom validations.
type DCRPluginFunc func(ctx Context, clientInfo *ClientMetaInfo)

type ClientMetaInfo struct {
	Name                               string                  `json:"client_name,omitempty" bson:"client_name,omitempty"`
	LogoURI                            string                  `json:"logo_uri,omitempty" bson:"logo_uri,omitempty"`
	RedirectURIS                       []string                `json:"redirect_uris" bson:"redirect_uris"`
	GrantTypes                         []GrantType             `json:"grant_types" bson:"grant_types"`
	ResponseTypes                      []ResponseType          `json:"response_types" bson:"response_types"`
	PublicJWKSURI                      string                  `json:"jwks_uri,omitempty" bson:"jwks_uri,omitempty"`
	PublicJWKS                         *JSONWebKeySet          `json:"jwks,omitempty" bson:"jwks,omitempty"`
	Scopes                             string                  `json:"scope" bson:"scope"`
	SubjectIdentifierType              SubjectIdentifierType   `json:"subject_type,omitempty" bson:"subject_type,omitempty"`
	IDTokenSignatureAlgorithm          jose.SignatureAlgorithm `json:"id_token_signed_response_alg,omitempty" bson:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncryptionAlgorithm      jose.KeyAlgorithm       `json:"id_token_encrypted_response_alg,omitempty" bson:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncryptionAlgorithm  jose.ContentEncryption  `json:"id_token_encrypted_response_enc,omitempty" bson:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignatureAlgorithm         jose.SignatureAlgorithm `json:"userinfo_signed_response_alg,omitempty" bson:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncryptionAlgorithm     jose.KeyAlgorithm       `json:"userinfo_encrypted_response_alg,omitempty" bson:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncryptionAlgorithm jose.ContentEncryption  `json:"userinfo_encrypted_response_enc,omitempty" bson:"userinfo_encrypted_response_enc,omitempty"`
	JARSignatureAlgorithm              jose.SignatureAlgorithm `json:"request_object_signing_alg,omitempty" bson:"request_object_signing_alg,omitempty"`
	JARKeyEncryptionAlgorithm          jose.KeyAlgorithm       `json:"request_object_encryption_alg,omitempty" bson:"request_object_encryption_alg,omitempty"`
	JARContentEncryptionAlgorithm      jose.ContentEncryption  `json:"request_object_encryption_enc,omitempty" bson:"request_object_encryption_enc,omitempty"`
	JARMSignatureAlgorithm             jose.SignatureAlgorithm `json:"authorization_signed_response_alg,omitempty" bson:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncryptionAlgorithm         jose.KeyAlgorithm       `json:"authorization_encrypted_response_alg,omitempty" bson:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncryptionAlgorithm     jose.ContentEncryption  `json:"authorization_encrypted_response_enc,omitempty" bson:"authorization_encrypted_response_enc,omitempty"`
	AuthnMethod                        ClientAuthnType         `json:"token_endpoint_auth_method" bson:"token_endpoint_auth_method"`
	AuthnSignatureAlgorithm            jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg,omitempty" bson:"token_endpoint_auth_signing_alg,omitempty"`
	DPoPIsRequired                     bool                    `json:"dpop_bound_access_tokens,omitempty" bson:"dpop_bound_access_tokens,omitempty"`
	TLSSubjectDistinguishedName        string                  `json:"tls_client_auth_subject_dn,omitempty" bson:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubjectAlternativeName represents a DNS name.
	TLSSubjectAlternativeName   string         `json:"tls_client_auth_san_dns,omitempty" bson:"tls_client_auth_san_dns,omitempty"`
	TLSSubjectAlternativeNameIp string         `json:"tls_client_auth_san_ip,omitempty" bson:"tls_client_auth_san_ip,omitempty"`
	AuthorizationDetailTypes    []string       `json:"authorization_data_types,omitempty" bson:"authorization_data_types,omitempty"`
	DefaultMaxAge               *int           `json:"default_max_age,omitempty" bson:"default_max_age,omitempty"`
	DefaultACRValues            string         `json:"default_acr_values,omitempty" bson:"default_acr_values,omitempty"`
	CustomAttributes            map[string]any `json:"custom_attributes,omitempty" bson:"custom_attributes,omitempty"`
}

func (c *ClientMetaInfo) SetAttribute(key string, value any) {
	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	c.CustomAttributes[key] = value
}
