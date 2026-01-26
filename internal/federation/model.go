package federation

import (
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	contentTypeEntityStatementJWT      = "application/entity-statement+jwt"
	contentTypeTrustChain              = "application/trust-chain+json"
	contentTypeExplicitRegistrationJWT = "application/explicit-registration-response+jwt"
	jwtTypeEntityStatement             = "entity-statement+jwt"
	jwtTypeTrustMark                   = "trust-mark+jwt"
	jwtTypeTrustMarkDelegation         = "trust-mark-delegation+jwt"
	jwtTypeExplicitRegistration        = "explicit-registration-response+jwt"
	federationEndpointPath             = "/.well-known/openid-federation"
)

type entityStatement struct {
	Issuer         string              `json:"iss"`
	Audience       string              `json:"aud,omitempty"`
	Subject        string              `json:"sub"`
	IssuedAt       int                 `json:"iat"`
	ExpiresAt      int                 `json:"exp"`
	JWKS           goidc.JSONWebKeySet `json:"jwks"`
	AuthorityHints []string            `json:"authority_hints,omitempty"`
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
	TrustMarkIssuers map[string][]string `json:"trust_mark_issuers,omitempty"`
	// TrustMarkOwners is used when a trust mark identifier is owned by an entity
	// different from the trust mark issuer, then that knowledge must be expressed in this claim.
	TrustMarkOwners map[string]struct {
		// Subject is the identifier of the trust mark owner.
		Subject string `json:"sub"`
		// JWKS is the owner's federation entity keys used for signing.
		JWKS goidc.JSONWebKeySet `json:"jwks"`
	} `json:"trust_mark_owners,omitempty"`
	// TrustAnchor is the identifier of the trust anchor in the trust chain.
	// This claim is specific to explicit registration responses; it is not a general entity statement claim.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	signed      string `json:"-"`
}

func (s entityStatement) Signed() string {
	return s.signed
}

// trustChain represents a sequence of entity statements forming a trust chain.
// A trust chain begins with an entity configuration that is the subject of the trust chain.
// The trust chain has zero or more subordinate statements issued by intermediates
// about their immediate subordinates, and includes the subordinate statement issued
// by the trust anchor about the top-most Intermediate (if there are intermediates)
// or the trust chain subject (if there are no intermediates).
// The trust chain always ends with the Entity Configuration of the trust anchor.
type trustChain []entityStatement

func (tc trustChain) subjectConfig() entityStatement {
	return tc[0]
}

func (tc trustChain) firstSubordinateStatement() entityStatement {
	return tc[1]
}

func (tc trustChain) authorityConfig() entityStatement {
	return tc[len(tc)-1]
}

// resolve processes a trust chain to determine the final entity statement.
func (chain trustChain) resolve() (entityStatement, error) {

	config := chain.subjectConfig()
	var policy metadataPolicy
	for _, authority := range chain[1:] {

		if authority.ExpiresAt < config.ExpiresAt {
			config.ExpiresAt = authority.ExpiresAt
		}

		if authority.MetadataPolicy == nil {
			continue
		}

		var err error
		policy, err = authority.MetadataPolicy.merge(policy)
		if err != nil {
			return entityStatement{}, err
		}
	}

	config.TrustAnchor = chain.authorityConfig().Subject
	return policy.apply(config)
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
