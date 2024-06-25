package models

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

type ClientMetaInfo struct {
	Name          string               `json:"client_name,omitempty" bson:"client_name,omitempty"`
	LogoUri       string               `json:"logo_uri,omitempty" bson:"logo_uri,omitempty"`
	RedirectUris  []string             `json:"redirect_uris" bson:"redirect_uris"`
	GrantTypes    []goidc.GrantType    `json:"grant_types" bson:"grant_types"`
	ResponseTypes []goidc.ResponseType `json:"response_types" bson:"response_types"`
	PublicJwksUri string               `json:"jwks_uri,omitempty" bson:"jwks_uri,omitempty"`
	// PublicJwks is pointer, because, if it is nil and PublicJwksUri is present,
	// we can fetch the content of PublicJwksUri and access the reference PublicJwks to cache the keys.
	// By doing so, we make sure to request PublicJwksUri at most once.
	PublicJwks                         *goidc.JsonWebKeySet        `json:"jwks,omitempty" bson:"jwks,omitempty"`
	Scopes                             string                      `json:"scope" bson:"scope"`
	SubjectIdentifierType              goidc.SubjectIdentifierType `json:"subject_type,omitempty" bson:"subject_type,omitempty"`
	IdTokenSignatureAlgorithm          jose.SignatureAlgorithm     `json:"id_token_signed_response_alg,omitempty" bson:"id_token_signed_response_alg,omitempty"`
	IdTokenKeyEncryptionAlgorithm      jose.KeyAlgorithm           `json:"id_token_encrypted_response_alg,omitempty" bson:"id_token_encrypted_response_alg,omitempty"`
	IdTokenContentEncryptionAlgorithm  jose.ContentEncryption      `json:"id_token_encrypted_response_enc,omitempty" bson:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignatureAlgorithm         jose.SignatureAlgorithm     `json:"userinfo_signed_response_alg,omitempty" bson:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncryptionAlgorithm     jose.KeyAlgorithm           `json:"userinfo_encrypted_response_alg,omitempty" bson:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncryptionAlgorithm jose.ContentEncryption      `json:"userinfo_encrypted_response_enc,omitempty" bson:"userinfo_encrypted_response_enc,omitempty"`
	JarSignatureAlgorithm              jose.SignatureAlgorithm     `json:"request_object_signing_alg,omitempty" bson:"request_object_signing_alg,omitempty"`
	JarKeyEncryptionAlgorithm          jose.KeyAlgorithm           `json:"request_object_encryption_alg,omitempty" bson:"request_object_encryption_alg,omitempty"`
	JarContentEncryptionAlgorithm      jose.ContentEncryption      `json:"request_object_encryption_enc,omitempty" bson:"request_object_encryption_enc,omitempty"`
	JarmSignatureAlgorithm             jose.SignatureAlgorithm     `json:"authorization_signed_response_alg,omitempty" bson:"authorization_signed_response_alg,omitempty"`
	JarmKeyEncryptionAlgorithm         jose.KeyAlgorithm           `json:"authorization_encrypted_response_alg,omitempty" bson:"authorization_encrypted_response_alg,omitempty"`
	JarmContentEncryptionAlgorithm     jose.ContentEncryption      `json:"authorization_encrypted_response_enc,omitempty" bson:"authorization_encrypted_response_enc,omitempty"`
	AuthnMethod                        goidc.ClientAuthnType       `json:"token_endpoint_auth_method" bson:"token_endpoint_auth_method"`
	AuthnSignatureAlgorithm            jose.SignatureAlgorithm     `json:"token_endpoint_auth_signing_alg,omitempty" bson:"token_endpoint_auth_signing_alg,omitempty"`
	DpopIsRequired                     bool                        `json:"dpop_bound_access_tokens,omitempty" bson:"dpop_bound_access_tokens,omitempty"`
	TlsSubjectDistinguishedName        string                      `json:"tls_client_auth_subject_dn,omitempty" bson:"tls_client_auth_subject_dn,omitempty"`
	// The DNS name.
	TlsSubjectAlternativeName   string         `json:"tls_client_auth_san_dns,omitempty" bson:"tls_client_auth_san_dns,omitempty"`
	TlsSubjectAlternativeNameIp string         `json:"tls_client_auth_san_ip,omitempty" bson:"tls_client_auth_san_ip,omitempty"`
	AuthorizationDetailTypes    []string       `json:"authorization_data_types,omitempty" bson:"authorization_data_types,omitempty"`
	Attributes                  map[string]any `json:"custom_attributes,omitempty" bson:"custom_attributes,omitempty"`
}

func (client ClientMetaInfo) GetName() (string, bool) {
	if client.Name == "" {
		return "", false
	}
	return client.Name, true
}

func (client ClientMetaInfo) GetLogoUri() (string, bool) {
	if client.LogoUri == "" {
		return "", false
	}
	return client.LogoUri, true
}

func (client ClientMetaInfo) GetScopes() (string, bool) {
	if client.Scopes == "" {
		return "", false
	}

	return client.Scopes, true
}

func (client *ClientMetaInfo) SetScopes(scopes string) {
	client.Scopes = scopes
}

// Get the client public JWKS either directly from the jwks attribute or using jwks_uri.
// This method also caches the keys if they are fetched from jwks_uri.
func (client ClientMetaInfo) GetPublicJwks() (goidc.JsonWebKeySet, error) {
	if client.PublicJwks != nil && len(client.PublicJwks.Keys) != 0 {
		return *client.PublicJwks, nil
	}

	if client.PublicJwksUri == "" {
		return goidc.JsonWebKeySet{}, NewOAuthError(goidc.InvalidRequest, "The client JWKS was informed neither by value or by reference")
	}

	jwks, err := unit.GetJwks(client.PublicJwksUri)
	if err != nil {
		return goidc.JsonWebKeySet{}, NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	// Cache the client JWKS.
	if client.PublicJwks != nil {
		client.PublicJwks.Keys = jwks.Keys
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

func (client *ClientMetaInfo) RequireDpop() {
	client.DpopIsRequired = true
}

type Client struct {
	Id string `json:"client_id" bson:"_id"`
	// This is used when the client authenticates with client_secret_jwt,
	// since the key used to sign the assertion is the same used to verify it.
	Secret string `json:"client_secret,omitempty" bson:"client_secret,omitempty"`
	// For client_secret_basic and client_secret_post, we only store the hash of the client secret.
	HashedSecret                  string `json:"hashed_secret,omitempty" bson:"hashed_secret,omitempty"`
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token" bson:"hashed_registration_access_token"`
	ClientMetaInfo
}

func (client Client) GetId() string {
	return client.Id
}

func (client Client) GetJwk(keyId string) (goidc.JsonWebKey, OAuthError) {
	jwks, oauthErr := client.GetPublicJwks()
	if oauthErr != nil {
		return goidc.JsonWebKey{}, NewOAuthError(goidc.InvalidRequest, oauthErr.Error())
	}

	keys := jwks.Key(keyId)
	if len(keys) == 0 {
		return goidc.JsonWebKey{}, NewOAuthError(goidc.InvalidClient, "invalid key ID")
	}

	return keys[0], nil
}

func (client Client) GetJarmEncryptionJwk() (goidc.JsonWebKey, OAuthError) {
	return client.getEncryptionJwk(client.JarmKeyEncryptionAlgorithm)
}

func (client Client) GetUserInfoEncryptionJwk() (goidc.JsonWebKey, OAuthError) {
	return client.getEncryptionJwk(client.UserInfoKeyEncryptionAlgorithm)
}

func (client Client) GetIdTokenEncryptionJwk() (goidc.JsonWebKey, OAuthError) {
	return client.getEncryptionJwk(client.IdTokenKeyEncryptionAlgorithm)
}

// Get the encryption JWK based match the algorithm.
func (client Client) getEncryptionJwk(algorithm jose.KeyAlgorithm) (goidc.JsonWebKey, OAuthError) {
	jwks, err := client.GetPublicJwks()
	if err != nil {
		return goidc.JsonWebKey{}, NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	for _, jwk := range jwks.Keys {
		if jwk.GetUsage() == string(goidc.KeyEncryptionUsage) && jwk.GetAlgorithm() == string(algorithm) {
			return jwk, nil
		}
	}

	return goidc.JsonWebKey{}, NewOAuthError(goidc.InvalidClient, fmt.Sprintf("invalid key algorithm: %s", algorithm))
}

func (client Client) AreScopesAllowed(requestedScopes string) bool {
	return unit.ContainsAllScopes(client.Scopes, requestedScopes)
}

func (client Client) IsResponseTypeAllowed(responseType goidc.ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsGrantTypeAllowed(grantType goidc.GrantType) bool {
	return slices.Contains(client.GrantTypes, grantType)
}

func (client Client) IsRedirectUriAllowed(redirectUri string) bool {
	for _, ru := range client.RedirectUris {
		if strings.HasPrefix(redirectUri, ru) {
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
