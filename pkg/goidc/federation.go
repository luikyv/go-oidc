package goidc

import "context"

type ClientRegistrationType string

const (
	ClientRegistrationTypeAutomatic ClientRegistrationType = "automatic"
	ClientRegistrationTypeExplicit  ClientRegistrationType = "explicit"
)

type RequiredTrustMarksFunc func(context.Context, *Client) []string

type OpenIDFedJWKSRepresentation string

const (
	OpenIDFedJWKSRepresentationInline    OpenIDFedJWKSRepresentation = "jwks"
	OpenIDFedJWKSRepresentationURI       OpenIDFedJWKSRepresentation = "jwk_uri"
	OpenIDFedJWKSRepresentationSignedURI OpenIDFedJWKSRepresentation = "signed_jwks_uri"
)
