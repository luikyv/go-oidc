package models

import (
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

//---------------------------------------- Client ----------------------------------------//

type ClientMetaInfo struct {
	RedirectUris              []string                        `json:"redirect_uris"`
	GrantTypes                []constants.GrantType           `json:"grant_type"`
	ResponseTypes             []constants.ResponseType        `json:"response_types"`
	ResponseModes             []constants.ResponseMode        `json:"response_modes"`
	PublicJwksUri             string                          `json:"jwks_uri"`
	PublicJwks                jose.JSONWebKeySet              `json:"jwks"`
	Scopes                    string                          `json:"scope"`
	SubjectIdentifierType     constants.SubjectIdentifierType `json:"subject_type"`
	IdTokenSignatureAlgorithm jose.SignatureAlgorithm         `json:"id_token_signed_response_alg"`
	JarSignatureAlgorithm     jose.SignatureAlgorithm         `json:"request_object_signing_alg"`
	PkceIsRequired            bool                            `json:"pkce_is_required"`
	AuthnMethod               constants.ClientAuthnType       `json:"token_endpoint_auth_method"`
	AuthnSignatureAlgorithm   jose.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg"`
	Attributes                map[string]string               `json:"custom_attributes"`
}

type Client struct {
	Id                            string `json:"client_id"`
	SecretSalt                    string `json:"secret_salt,omitempty"`
	HashedSecret                  string `json:"hashed_secret,omitempty"`
	Secret                        string `json:"client_secret,omitempty"`
	HashedRegistrationAccessToken string `json:"hashed_registration_access_token"`
	ClientMetaInfo
}

func (c Client) GetPublicJwks() jose.JSONWebKeySet {
	// TODO: use the uri
	return c.PublicJwks
}

func (client Client) AreScopesAllowed(requestedScopes []string) bool {
	return unit.ContainsAll(unit.SplitStringWithSpaces(client.Scopes), requestedScopes...)
}

func (client Client) IsResponseTypeAllowed(responseType constants.ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsResponseModeAllowed(responseMode constants.ResponseMode) bool {
	return slices.Contains(client.ResponseModes, responseMode)
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

func (client Client) GetSigningAlgorithms() []jose.SignatureAlgorithm {
	return getSigningAlgorithms(client.PublicJwks)
}

func getSigningAlgorithms(jwks jose.JSONWebKeySet) []jose.SignatureAlgorithm {
	signingAlgorithms := []jose.SignatureAlgorithm{}
	for _, jwk := range jwks.Keys {
		signingAlgorithms = append(signingAlgorithms, jose.SignatureAlgorithm(jwk.Algorithm))
	}
	return signingAlgorithms
}
