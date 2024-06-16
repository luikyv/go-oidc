package models

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

//---------------------------------------- Client ----------------------------------------//

type ClientMetaInfo struct {
	Name          string                   `json:"client_name,omitempty"`
	LogoUri       string                   `json:"logo_uri,omitempty"`
	RedirectUris  []string                 `json:"redirect_uris"`
	GrantTypes    []constants.GrantType    `json:"grant_types"`
	ResponseTypes []constants.ResponseType `json:"response_types"`
	PublicJwksUri string                   `json:"jwks_uri,omitempty"`
	// PublicJwks is pointer, because, if it is nil and PublicJwksUri is present,
	// we can fetch the content of PublicJwksUri and access the reference PublicJwks to cache the keys.
	// By doing so, we make sure to request PublicJwksUri at most once.
	PublicJwks                        *jose.JSONWebKeySet             `json:"jwks"`
	Scopes                            string                          `json:"scope"`
	SubjectIdentifierType             constants.SubjectIdentifierType `json:"subject_type,omitempty"`
	IdTokenSignatureAlgorithm         jose.SignatureAlgorithm         `json:"id_token_signed_response_alg,omitempty"`
	IdTokenKeyEncryptionAlgorithm     jose.KeyAlgorithm               `json:"id_token_encrypted_response_alg,omitempty"`
	IdTokenContentEncryptionAlgorithm jose.ContentEncryption          `json:"id_token_encrypted_response_enc,omitempty"`
	JarSignatureAlgorithm             jose.SignatureAlgorithm         `json:"request_object_signing_alg,omitempty"`
	JarmSignatureAlgorithm            jose.SignatureAlgorithm         `json:"authorization_signed_response_alg,omitempty"`
	PkceIsRequired                    bool                            `json:"pkce_is_required"`
	AuthnMethod                       constants.ClientAuthnType       `json:"token_endpoint_auth_method"`
	AuthnSignatureAlgorithm           jose.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg"`
	DpopIsRequired                    bool                            `json:"dpop_bound_access_tokens,omitempty"`
	UserInfoSignatureAlgorithm        jose.SignatureAlgorithm         `json:"userinfo_signed_response_alg,omitempty"`
	TlsSubjectDistinguishedName       string                          `json:"tls_client_auth_subject_dn,omitempty"`
	// The DNS name.
	TlsSubjectAlternativeName   string            `json:"tls_client_auth_san_dns,omitempty"`
	TlsSubjectAlternativeNameIp string            `json:"tls_client_auth_san_ip,omitempty"`
	Attributes                  map[string]string `json:"custom_attributes"`
}

type Client struct {
	Id string `json:"client_id"`
	// This is used when the client authenticates with client_secret_jwt,
	// since the key used to sign the assertion is the same used to verify it.
	Secret string `json:"client_secret,omitempty"`
	// For client_secret_basic and client_secret_post, we only store the hash of the client secret.
	HashedSecret                  string `json:"hashed_secret,omitempty"`
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token"`
	ClientMetaInfo
}

// Get the client public JWKS either directly from the jwks attribute or using jwks_uri.
// This method also caches the keys if they are fetched from jwks_uri.
func (client Client) GetPublicJwks() (jose.JSONWebKeySet, OAuthError) {
	if client.PublicJwks != nil && len(client.PublicJwks.Keys) != 0 {
		return *client.PublicJwks, nil
	}

	jwks, err := unit.GetJwks(client.PublicJwksUri)
	if err != nil {
		return jose.JSONWebKeySet{}, NewOAuthError(constants.InvalidRequest, err.Error())
	}

	// Cache the client JWKS.
	if client.PublicJwks != nil {
		client.PublicJwks.Keys = jwks.Keys
	}

	return jwks, nil
}

func (client Client) GetJwk(keyId string) (jose.JSONWebKey, OAuthError) {
	jwks, oauthErr := client.GetPublicJwks()
	if oauthErr != nil {
		return jose.JSONWebKey{}, oauthErr
	}

	keys := jwks.Key(keyId)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, NewOAuthError(constants.InvalidClient, "invalid key ID")
	}

	return keys[0], nil
}

func (client Client) GetIdTokenEncryptionJwk() (jose.JSONWebKey, OAuthError) {
	return client.getEncryptionJwk(client.IdTokenKeyEncryptionAlgorithm)
}

// Get the encryption JWK based on the "alg" claim.
func (client Client) getEncryptionJwk(algorithm jose.KeyAlgorithm) (jose.JSONWebKey, OAuthError) {
	jwks, err := client.GetPublicJwks()
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	for _, jwk := range jwks.Keys {
		if jwk.Use == string(constants.KeyEncryptionUsage) && jwk.Algorithm == string(algorithm) {
			return jwk, nil
		}
	}

	return jose.JSONWebKey{}, NewOAuthError(constants.InvalidClient, fmt.Sprintf("invalid key algorithm: %s", algorithm))
}

func (client Client) AreScopesAllowed(requestedScopes string) bool {
	return unit.ContainsAll(unit.SplitStringWithSpaces(client.Scopes), unit.SplitStringWithSpaces(requestedScopes)...)
}

func (client Client) IsResponseTypeAllowed(responseType constants.ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsGrantTypeAllowed(grantType constants.GrantType) bool {
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

func (client Client) IsRegistrationAccessTokenValid(registrationAccessToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedRegistrationAccessToken), []byte(registrationAccessToken))
	return err == nil
}

func (client Client) GetCustomAttribute(key string) string {
	return client.Attributes[key]
}
