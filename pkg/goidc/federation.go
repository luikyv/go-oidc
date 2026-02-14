package goidc

import "context"

type ClientRegistrationType string

const (
	ClientRegistrationTypeAutomatic ClientRegistrationType = "automatic"
	ClientRegistrationTypeExplicit  ClientRegistrationType = "explicit"
)

type RequiredTrustMarksFunc func(context.Context, *Client) []TrustMark

type TrustMark string

type JWKSRepresentation string

const (
	JWKSRepresentationInline    JWKSRepresentation = "jwks"
	JWKSRepresentationURI       JWKSRepresentation = "jwk_uri"
	JWKSRepresentationSignedURI JWKSRepresentation = "signed_jwks_uri"
)
