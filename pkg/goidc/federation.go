package goidc

import (
	"context"
)

type EntityStatement struct {
	Issuer         string        `json:"iss"`
	Subject        string        `json:"sub"`
	IssuedAt       int           `json:"iat"`
	ExpiresAt      int           `json:"exp"`
	JWKS           JSONWebKeySet `json:"jwks"`
	AuthorityHints []string      `json:"authority_hints,omitempty"`
	Metadata       struct {
		FederationAuthority *FederationAuthority `json:"federation_entity,omitempty"`
		OpenIDProvider      *Configuration       `json:"openid_provider,omitempty"`
		OpenIDClient        *ClientMeta          `json:"openid_relying_party,omitempty"`
	} `json:"metadata"`
	Critical   []string `json:"crit,omitempty"`
	TrustMarks []struct {
		Type      TrustMark `json:"trust_mark_type"`
		TrustMark string    `json:"trust_mark"`
	} `json:"trust_marks,omitempty"`
}

type FederationAuthority struct {
	FetchEndpoint                string        `json:"federation_fetch_endpoint,omitempty"`
	FetchEndpointAuthMethods     []AuthnMethod `json:"federation_fetch_endpoint_auth_methods,omitempty"`
	ListEndpoint                 string        `json:"federation_list_endpoint,omitempty"`
	ResolveEndpoint              string        `json:"federation_resolve_endpoint,omitempty"`
	TrustMarkStatusEndpoint      string        `json:"federation_trust_mark_status_endpoint,omitempty"`
	TrustMarkListEndpoint        string        `json:"federation_trust_mark_list_endpoint,omitempty"`
	TrustMarkEndpoint            string        `json:"federation_trust_mark_endpoint,omitempty"`
	TrustMarkEndpointAuthMethods []AuthnMethod `json:"federation_trust_mark_endpoint_auth_methods,omitempty"`
	HistoricalKeysEndpoint       string        `json:"federation_historical_keys_endpoint,omitempty"`
	// EndpointAuthSigAlgValuesSupported are the algorithms for signing the JWT
	// used for private_key_jwt when authenticating to federation endpoints.
	EndpointAuthSigAlgValuesSupported []SignatureAlgorithm `json:"endpoint_auth_signing_alg_values_supported,omitempty"`
	OrganizationName                  string               `json:"organization_name,omitempty"`
}

type ClientRegistrationType string

const (
	ClientRegistrationTypeAutomatic ClientRegistrationType = "automatic"
	ClientRegistrationTypeExplicit  ClientRegistrationType = "explicit"
)

type RequiredTrustMarksFunc func(context.Context, *Client) []TrustMark

type TrustMark string

type TrustMarkConfig struct {
	Issuer string
	Mark   TrustMark
}

type JWKSRepresentation string

const (
	JWKSRepresentationInline    JWKSRepresentation = "jwks"
	JWKSRepresentationURI       JWKSRepresentation = "jwks_uri"
	JWKSRepresentationSignedURI JWKSRepresentation = "signed_jwks_uri"
)
