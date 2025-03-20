package federation

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	entityStatementJWTType        = "entity-statement+jwt"
	entityStatementJWTContentType = "application/entity-statement+jwt"
	trustMarkJWTType              = "trust-mark+jwt"
	trustMarkDelegationJWTType    = "trust-mark-delegation+jwt"
	federationEndpointPath        = "/.well-known/openid-federation"
)

type entityStatement struct {
	Issuer         string             `json:"iss"`
	Subject        string             `json:"sub"`
	IssuedAt       int                `json:"iat"`
	ExpiresAt      int                `json:"exp"`
	JWKS           jose.JSONWebKeySet `json:"jwks"`
	AuthorityHints []string           `json:"authority_hints,omitempty"`
	Metadata       struct {
		FederationAuthority *federationAuthority `json:"federation_entity,omitempty"`
		OpenIDProvider      *openIDProvider      `json:"openid_provider,omitempty"`
		OpenIDClient        *openIDClient        `json:"openid_relying_party,omitempty"`
	} `json:"metadata"`
	MetadataPolicy *metadataPolicy `json:"metadata_policy,omitempty"`
	TrustMarks     []struct {
		ID        string `json:"id"`
		TrustMark string `json:"trust_mark"`
	} `json:"trust_marks,omitempty"`
	// TrustMarkIssuers may be used by a trust anchor to tell which combination
	// of trust mark identifiers and issuers are trusted by the federation.
	// It is a JSON object with member names that are trust mark identifiers and
	// each corresponding value being an array of entity identifiers that are
	// trusted to represent the accreditation authority for trust marks with that identifier.
	// If the array following a Trust Mark identifier is empty, anyone may issue
	// trust marks with that identifier.
	TrustMarkIssuers map[string][]string `json:"trust_mark_issuers"`
	// TrustMarkOwners is used when a trust mark identifier is owned by an entity
	// different from the trust mark issuer, then that knowledge must be expressed in this claim.
	TrustMarkOwners map[string]struct {
		// Subject is the identifier of the trust mark owner.
		Subject string `json:"sub"`
		// JWKS is the owner's federation entity keys used for signing.
		JWKS jose.JSONWebKeySet `json:"jwks"`
	} `json:"trust_mark_owners"`
	signed string `json:"-"`
}

func (s entityStatement) Signed() string {
	return s.signed
}

type trustChain []entityStatement

func (tc trustChain) entityConfig() entityStatement {
	return tc[0]
}

func (tc trustChain) authorityConfig() entityStatement {
	return tc[len(tc)-1]
}

type openIDProvider struct {
	ClientRegistrationTypes        []goidc.ClientRegistrationType `json:"client_registration_types_supported"`
	FederationRegistrationEndpoint string                         `json:"federation_registration_endpoint,omitempty"`
	discovery.OpenIDConfiguration
}

type openIDClient struct {
	ClientRegistrationTypes []goidc.ClientRegistrationType `json:"client_registration_types"`
	goidc.ClientMeta
}

type federationAuthority struct {
	FetchEndpoint    string `json:"federation_fetch_endpoint"`
	ListEndpoint     string `json:"federation_list_endpoint"`
	ResolveEndpoint  string `json:"federation_resolve_endpoint"`
	OrganizationName string `json:"organization_name"`
}

type trustMark struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	ID         string `json:"trust_mark_id"`
	IssuedAt   int    `json:"iat"`
	ExpiresAt  int    `json:"exp"`
	Delegation string `json:"delegation"`
}
