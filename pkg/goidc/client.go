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
	// This is used when the client authenticates with client_secret_jwt,
	// since the key used to sign the assertion is the same used to verify it.
	Secret string `json:"client_secret,omitempty" bson:"client_secret,omitempty"`
	// For client_secret_basic and client_secret_post, we only store the hash of the client secret.
	HashedSecret                  string `json:"hashed_secret,omitempty" bson:"hashed_secret,omitempty"`
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token" bson:"hashed_registration_access_token"`
	ClientMetaInfo
}

func (client Client) GetJWK(keyID string) (JSONWebKey, OAuthError) {
	jwks, oauthErr := client.GetPublicJWKS()
	if oauthErr != nil {
		return JSONWebKey{}, NewOAuthError(InvalidRequest, oauthErr.Error())
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return JSONWebKey{}, NewOAuthError(InvalidClient, "invalid key ID")
	}

	return keys[0], nil
}

func (client Client) GetJARMEncryptionJWK() (JSONWebKey, OAuthError) {
	return client.getEncryptionJWK(client.JARMKeyEncryptionAlgorithm)
}

func (client Client) GetUserInfoEncryptionJWK() (JSONWebKey, OAuthError) {
	return client.getEncryptionJWK(client.UserInfoKeyEncryptionAlgorithm)
}

func (client Client) GetIDTokenEncryptionJWK() (JSONWebKey, OAuthError) {
	return client.getEncryptionJWK(client.IDTokenKeyEncryptionAlgorithm)
}

// Get the encryption JWK based match the algorithm.
func (client Client) getEncryptionJWK(algorithm jose.KeyAlgorithm) (JSONWebKey, OAuthError) {
	jwks, err := client.GetPublicJWKS()
	if err != nil {
		return JSONWebKey{}, NewOAuthError(InvalidRequest, err.Error())
	}

	for _, jwk := range jwks.Keys {
		if jwk.GetUsage() == string(KeyEncryptionUsage) && jwk.GetAlgorithm() == string(algorithm) {
			return jwk, nil
		}
	}

	return JSONWebKey{}, NewOAuthError(InvalidClient, fmt.Sprintf("invalid key algorithm: %s", algorithm))
}

func (client Client) AreScopesAllowed(requestedScopes string) bool {
	return ContainsAllScopes(client.Scopes, requestedScopes)
}

func (client Client) IsResponseTypeAllowed(responseType ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsGrantTypeAllowed(grantType GrantType) bool {
	return slices.Contains(client.GrantTypes, grantType)
}

func (client Client) IsRedirectURIAllowed(redirectURI string) bool {
	for _, ru := range client.RedirectURIS {
		if strings.HasPrefix(redirectURI, ru) {
			return true
		}
	}
	return false
}

func (client Client) IsAuthorizationDetailTypeAllowed(authDetailType string) bool {
	// If the client didn't announce the authorization types it will use, consider any value valid.
	if client.AuthorizationDetailTypes == nil {
		return true
	}

	return slices.Contains(client.AuthorizationDetailTypes, authDetailType)
}

func (client Client) IsRegistrationAccessTokenValid(registrationAccessToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedRegistrationAccessToken), []byte(registrationAccessToken))
	return err == nil
}

// Function that will be executed during DCR and DCM.
// It can be used to modify the client and perform custom validations.
type DCRPluginFunc func(ctx Context, dynamicClient *DynamicClient)

type DynamicClient struct {
	ID string
	// This value is filled with the authorization header when creating a client with DCR.
	InitialAccessToken string
	// This value is filled with the authorization header for all DCM requests.
	RegistrationAccessToken string
	Secret                  string
	ClientMetaInfo
}

type ClientMetaInfo struct {
	Name          string         `json:"client_name,omitempty" bson:"client_name,omitempty"`
	LogoURI       string         `json:"logo_uri,omitempty" bson:"logo_uri,omitempty"`
	RedirectURIS  []string       `json:"redirect_uris" bson:"redirect_uris"`
	GrantTypes    []GrantType    `json:"grant_types" bson:"grant_types"`
	ResponseTypes []ResponseType `json:"response_types" bson:"response_types"`
	PublicJWKSURI string         `json:"jwks_uri,omitempty" bson:"jwks_uri,omitempty"`
	// PublicJWKS is pointer, because, if it is nil and PublicJWKSURI is present,
	// we can fetch the content of PublicJWKSURI and access the reference PublicJWKS to cache the keys.
	// By doing so, we make sure to request PublicJWKSURI at most once.
	PublicJWKS                         *JSONWebKeySet          `json:"jwks,omitempty" bson:"jwks,omitempty"`
	Scopes                             string                  `json:"scope" bson:"scope"`
	SubjectIDentifierType              SubjectIDentifierType   `json:"subject_type,omitempty" bson:"subject_type,omitempty"`
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
	DPOPIsRequired                     bool                    `json:"dpop_bound_access_tokens,omitempty" bson:"dpop_bound_access_tokens,omitempty"`
	TLSSubjectDistinguishedName        string                  `json:"tls_client_auth_subject_dn,omitempty" bson:"tls_client_auth_subject_dn,omitempty"`
	// The DNS name.
	TLSSubjectAlternativeName   string         `json:"tls_client_auth_san_dns,omitempty" bson:"tls_client_auth_san_dns,omitempty"`
	TLSSubjectAlternativeNameIp string         `json:"tls_client_auth_san_ip,omitempty" bson:"tls_client_auth_san_ip,omitempty"`
	AuthorizationDetailTypes    []string       `json:"authorization_data_types,omitempty" bson:"authorization_data_types,omitempty"`
	Attributes                  map[string]any `json:"custom_attributes,omitempty" bson:"custom_attributes,omitempty"`
}

// Get the client public JWKS either directly from the jwks attribute or using jwks_uri.
// This method also caches the keys if they are fetched from jwks_uri.
func (client ClientMetaInfo) GetPublicJWKS() (JSONWebKeySet, error) {
	if client.PublicJWKS != nil && len(client.PublicJWKS.Keys) != 0 {
		return *client.PublicJWKS, nil
	}

	if client.PublicJWKSURI == "" {
		return JSONWebKeySet{}, NewOAuthError(InvalidRequest, "The client JWKS was informed neither by value or by reference")
	}

	jwks, err := GetJWKS(client.PublicJWKSURI)
	if err != nil {
		return JSONWebKeySet{}, NewOAuthError(InvalidRequest, err.Error())
	}

	// Cache the client JWKS.
	if client.PublicJWKS != nil {
		client.PublicJWKS.Keys = jwks.Keys
	}

	return jwks, nil
}

func (client *ClientMetaInfo) SetAttribute(key string, value any) {
	if client.Attributes == nil {
		client.Attributes = make(map[string]any)
	}
	client.Attributes[key] = value
}

func (client ClientMetaInfo) GetAttribute(key string) (any, bool) {
	value, ok := client.Attributes[key]
	return value, ok
}
